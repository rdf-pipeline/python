#!/usr/bin/env python3

# Virtualenv:
# https://scoutapm.com/blog/python-flask-tutorial-getting-started-with-flask
# To run (in the virtualenv):
#   $ source bin/activate
#   $ export FLASK_APP=app.py
#   $ export FLASK_ENV=development
#   $ export FLASK_DEBUG=1
#   $ flask run

# app.py

import time
from flask import Flask, render_template, request
from urllib.parse import urlparse
import urllib.request
import netifaces
import os
import sys
import inspect
import reprlib
import socket
import functools
from urllib.parse import urlparse, urlunparse
from url_normalize import url_normalize
import re
import pathlib
import json

#######################################################################
###################### Global constants ###########################
#######################################################################

global RDF_PIPELINE_DEV_DIR
RDF_PIPELINE_DEV_DIR = None
global PATH
PATH = None

def SetEnvDefault(yourDict, yourKey, defaultValue):
    yourDict[yourKey] = yourDict.get(yourKey, defaultValue)

SetEnvDefault(os.environ, 'DOCUMENT_ROOT', "/var/www")
### TODO: Set $baseUri properly.  Needs port?
SetEnvDefault(os.environ, 'SERVER_NAME', "localhost")
SERVER_NAME = os.environ.get('SERVER_NAME', '')
SetEnvDefault(os.environ, 'SERVER_SCHEME', "http")
SERVER_SCHEME = os.environ.get('SERVER_SCHEME', '')
if SERVER_SCHEME not in ['http', 'https'] :
    raise ValueError(f'$SERVER_SCHEME must be "http" or "https": "{SERVER_SCHEME}"')
# SERVER_PORT must be set as a string.
SetEnvDefault(os.environ, 'SERVER_PORT', "5000")
SERVER_PORT = os.environ.get('SERVER_PORT', '')
# Default port for http is 80; https is 443.
if (SERVER_SCHEME == 'http' and SERVER_PORT == '80') or (SERVER_PORT == 'https' and SERVER_PORT == '443') :
    Warn(f"[WARNING] Setting $SERVER_PORT={SERVER_PORT} to '', because it was the default for $SERVER_SCHEME={SERVER_SCHEME}")
    os.environ['SERVER_PORT'] = ''
    SERVER_PORT = ''


#######################################################################
###################### Functions start here ###########################
#######################################################################

######################### die ########################
# Replacement for perl's die
def die(error_message):
    raise Exception(error_message)

################ LocalIps #################
# Return all the IPs by which this host is locally known.
# Results are cached for fast repeated lookup.
# Works for all my known local hostnames or IP addresses, e.g.,
# 127.0.0.1 192.168.90.152 10.8.0.54 localhost dbooth-t470p
# This function might not be needed.
def LocalIps():
    if not hasattr(LocalIps, "_localIps") :
        # https://stackoverflow.com/questions/270745/how-do-i-determine-all-of-my-ip-addresses-when-i-have-multiple-nics#answer-33946251
        LocalIps._localIps = set([netifaces.ifaddresses(iface)[netifaces.AF_INET][0]['addr'] for iface in netifaces.interfaces() if netifaces.AF_INET in netifaces.ifaddresses(iface)])
        # https://stackoverflow.com/questions/270745/how-do-i-determine-all-of-my-ip-addresses-when-i-have-multiple-nics#answer-16412986
        LocalIps._localIps.update([i[4][0] for i in socket.getaddrinfo(socket.gethostname(), None)])
    #### TODO: is there an IPv6 localhost convention that also needs to be checked?
    #### TODO: Do I really need to check for the ^127\. pattern?
    # WarnLine("LocalIps: " + " ".join(LocalIps._localIps))
    return(LocalIps._localIps)

################ IsCurrentWebServer #################
# Is the given host name, which may be either a domain name or
# an IP address, hosted on this same web server?
# This is used to canonicalize URIs in a pipeline definition, so
# that we can determine whether a request made to a URI would actually
# (recursively) go to the current web server, which we need to avoid.
# My laptop is currently accessible by these IPs:
# # 127.0.0.1 192.168.90.152 10.8.0.54 localhost dbooth-t470p
# When flask is run in dev mode, it normally only responds
# to requests made to localhost (which is 127.0.0.1),
# whereas in production mode (run with --host=0.0.0.0) it will respond to
# external requests, i.e., requests to any of the above IP addresses.  
# This means that, although in dev mode flask
# won't respond to requests made to 192.168.90.152 (for example),
# the framework should still work, because it will canonicalize
# that IP to localhost, recognize it as the current web server host,
# and avoid making an HTTP request anyway.
# Results are cached for fast repeated lookup.
@functools.lru_cache(maxsize=None)
def IsCurrentWebServer(host, port=None):
    # First compare the ports.  If the ports differ then its a different
    # web server.
    # Default them to '' for easier comparison:
    p = '' if port is None else port
    sp = '' if SERVER_PORT is None else SERVER_PORT
    if p != sp :
        Warn(f"IsCurrentWebServer SERVER_PORT={sp} port={p}")
        Warn(f"IsCurrentWebServer SERVER_PORT != port; returning False")
        return False
    # Now compare the hostname.  This is more complex because we need
    # to consider aliases that go to the same IP address.  We used to
    # also consider multiple IP addresses for this server, but I think
    # that was wrong, since I think the server only listens on one
    # IP address.
    try:
        #### TODO: is there an IPv6 localhost convention that also needs to be checked?
        # Warn("Calling gethostbyname...")
        h_ip = socket.gethostbyname(host)
        sn_ip = socket.gethostbyname(SERVER_NAME)
        # Warn(f"h_ip: {h_ip} sn_ip: {sn_ip}")
        if h_ip == sn_ip :
            # Warn(f"IsCurrentWebServer host is local; returning True")
            return True
    except OSError as error:
        # As a sanity check, make sure we can get the localhost IP.
        # If not, re-throw the original exception because we cannot run:
        try:
            localhostIp = socket.gethostbyname('localhost')
        except OSError:
            raise error
        # Inability to resolve a given host is non-fatal.  We consider
        # the host non-local:
        # Warn(f"IsCurrentWebServer returning False 3")
        return False
    # Warn(f"IsCurrentWebServer non-local IP -- returning False 2")
    return False

def OLD_IsCurrentWebServer(host, port=None):
    # This version is OBSOLETE.  It wrongly checks *all* IP addresses
    # of the current server, instead of only checking the one that
    # we are running on.
    #
    # First compare the ports.  If the ports differ then its a different
    # web server.
    # Default them to '' for easier comparison:
    p = '' if port is None else port
    sp = '' if SERVER_PORT is None else SERVER_PORT
    if p != sp :
        # Warn(f"IsCurrentWebServer SERVER_PORT={sp} port={p}")
        # Warn(f"IsCurrentWebServer SERVER_PORT != port; returning False")
        return False
    # Now compare the hostname.  This is more complex because we need
    # to consider aliases that go to the same IP address.  We used to
    # also consider multiple IP addresses for this server, but I think
    # that was wrong, since I think the server only listens on one
    # IP address.
    try:
        #### TODO: is there an IPv6 localhost convention that also needs to be checked?
        ip = socket.gethostbyname(host)
        localIps = LocalIps()
        if not (ip in localIps) :
            # Warn(f"IsCurrentWebServer non-local IP -- returning False 2")
            return False
    except OSError as error:
        # As a sanity check, make sure we can get the localhost IP.
        # If not, re-throw the original exception because we cannot run:
        try:
            localhostIp = socket.gethostbyname('localhost')
        except OSError:
            raise error
        # Inability to resolve a given host is non-fatal.  We consider
        # the host non-local:
        # Warn(f"IsCurrentWebServer returning False 3")
        return False
    # IP is local.
    # Warn(f"IsCurrentWebServer host is local; returning True")
    return True

################ CanonicalizeUri #################
# Canonicalize the given URI:  If it is an absolute local http URI,
# then canonicalize it to $SERVER_NAME localhost or 127.0.0.1 .
# Other URIs are passed through unchanged.
# The reason for canonicalizing only node URIs on this web server is because
# the RDF Pipeline Framework will be handling requests for them, so
# it needs to be able to distinguish them from foreign URIs, both
# to avoid an infinite recursion of HTTP requests and to lookup
# metadata based on the URI.  If the URI were a synonym, such as
# http://127.0.0.1/node/foo instead of http://localhost/node/foo ,
# then the metadata lookup would fail to find the metadata.
canonicalizedUriCache = {}
def CanonicalizeUri(oldUri):
    Warn(f"CanonicalizeUri({oldUri})")
    global canonicalizedUriCache
    if oldUri in canonicalizedUriCache :
        Warn(f"CanonicalizeUri returning cached:({canonicalizedUriCache[oldUri]})")
        return canonicalizedUriCache[oldUri]
    # Pass it through url_normalize before parsing, 
    # to get rid of any default port:
    oldParsed = urlparse(url_normalize(oldUri))
    host = oldParsed.hostname
    # Convert port to string:
    port = '' if oldParsed.port is None else str(oldParsed.port)
    # Warn(f"CanonicalizeUri host: {host} port: {port}")
    if not IsCurrentWebServer(host, port) :
        Warn(f"CanonicalizeUri not IsCurrentWS; returning oldUri: {oldUri}")
        canonicalizedUriCache[oldUri] = oldUri
        return oldUri
    # Prefer SERVER_NAME over localhost or 127.0.0.1
    localUri = oldUri
    if host != SERVER_NAME :
        # Warn(f"CanonicalizeUri using SERVER_NAME: {SERVER_NAME}")
        netloc = SERVER_NAME
        if (port is not None and port != '') : 
            netloc += f':{port}'
        # Warn(f"CanonicalizeUri netloc: {netloc}")
        localUri = urlunparse(oldParsed._replace(netloc=netloc))
        # Warn(f"CanonicalizeUri localUri: {localUri}")
    # url_normalize adds a slash if needed, but we don't want it.
    # TODO: Figure out the impact of removing the final slash.
    if oldUri[-1] != '/' and localUri[-1] == '/' :
        # Warn(f"CanonicalizeUri removing trailing slash")
        localUri = localUri[0:-1]
    canonicalizedUriCache[oldUri] = localUri
    Warn(f"CanonicalizeUri returning: {localUri}")
    return localUri

########## ReadFile ############
def ReadFile(filename):
    with open(filename, "r", encoding='utf-8') as f:
        return f.read()

####################### WriteFile #####################
# UTF-8 python3
def WriteFile(filename, s):
    with open(filename, "w", encoding="utf8") as f:
        f.write(s)

####################### AppendFile #####################
# UTF-8 python3
def AppendFile(filename, s):
    with open(filename, "a+", encoding="utf8") as f:
        f.write(s)

################# findall_sub #####################
# Python3 function to perform string substitution while
# also returning group matches.
def findall_sub(pattern, repl, string, count=0, flags=0):
    """ Call findall and sub, and return a tuple: newString, matches """
    newString = string
    matches = re.findall(pattern, string, flags)
    if (matches) :
        newString = re.sub(pattern, repl, string, count, flags)
    return newString, matches

########## PrintLog ############
def PrintLog(msgs):
    global logFile;
    AppendFile(logFile, msgs)

########## WarnLine ############
def WarnLine(msg, level=0):
    Warn(msg + "\n")

########## Warn ############
# Log a warning if the current $debug >= $level for this warning.
# This will go to the apache error log: /var/log/apache2/error.log
# and also to $logFile .
def Warn(msg, level=0):
    global debugStackDepth
    global debug
    # As a debugging convenience, force a newline at the end:
    if not msg.endswith('\n') :
        msg = msg + "\n";
    if debug is None :
        # sys.stderr.write("debug not defined!\n") 
        raise NameError("debug not defined!\n") 
    if level is not None and debug < level :
        return 1
    maxRecursion = 30
    # depth = debugStackDepth + &CallStackDepth() -2;
    depth = debugStackDepth + len(inspect.stack(0)) - debugStackDepthOffset
    if depth >= maxRecursion :
        raise RecursionError(f"PANIC!!!  Deep recursion > {maxRecursion}! debug {debug} \n Maybe a cycle in the pipeline graph?\n")
    indent = depth *2
    # Additional indent like Warn("  One\nTwo\n") will be applied to
    # all lines in the given string also, producing:
    #     One
    #     Two
    moreSpaces = "";
    # $moreSpaces = $1 if $msg =~ s/^(\s+)//;
    # findall_sub(pattern, repl, string, count=0, flags=0):
    msg, matches = findall_sub(r'^(\s+)', '', msg)
    if (matches) :
        # $msg =~ s/^/$spaces/mg;
        moreSpaces = matches[0]
    spaces = (" " * indent) + moreSpaces
    # When there is a newline at the end, perl prevents it from
    # matching ^, but python doesn't, which adds extra indent at the end.  
    # To work around this problem and prevent extra spaces
    # after the final newline, we use ^(?=.|\n) here instead.
    # msg = re.sub(r'^', spaces, msg, flags=re.MULTILINE)
    msg = re.sub(r'^(?=.|\n)', spaces, msg, flags=re.MULTILINE)
    PrintLog(msg)
    #### TODO: Is this test needed?  It looks like a debugging remnant.
    global configLastModified
    if configLastModified is None :
        sys.stderr.write("configLastModified not defined!\n")
    # if !defined($level) || $debug >= $level;
    if level is None or debug >= level :
        sys.stderr.write(msg)
    return 1

#################################################################
####################### Global Variables ########################
#################################################################

logFile = "/tmp/rdf-pipeline-log.txt"
timingLogFile = "/tmp/rdf-pipeline-timing.tsv"
# unlink $logFile || die;

# Find the directory where this script is running
script_dirname = os.path.realpath(sys.path[0])

isLocal = {}        # Cache for IsCurrentWebServer
localIp = None      # IP address of this host

######################### Node Types ########################
# TODO: use RDF::Pipeline::ExampleHtmlNode;
# TODO: use RDF::Pipeline::GraphNode;

##################  Debugging and testing ##################
# debug verbosity:
DEBUG_OFF = 0     # No debug output.  Warnings/errors only.
DEBUG_NODE_UPDATES = 1    # Show nodes updated.
DEBUG_PARAM_UPDATES = 2;   # Also show parameters updated.
DEBUG_CACHES = 3  # Also show caches updated.
DEBUG_CHANGES = 4         # Also show them unchanged.  This verbosity is normally used for regression testing.
DEBUG_REQUESTS = 5        # Also show requests.
DEBUG_DETAILS = 6 # Show requests plus more detail.

# debug level is set using an env var:
debug = int(os.getenv('RDF_PIPELINE_DEBUG', str(DEBUG_CHANGES)))
rawDebug = debug;
# Allows symbolic $debug value (not supported in python version):
# $debug = eval $debug if defined($debug) && $debug =~ m/^\$\w+$/;

debugStackDepth = 0       # Used for indenting debug messages.
# Compensate for flask stack depth:
debugStackDepthOffset = len(inspect.stack(0)) + 6
test = None     # For testing outside of apache2

################### Runtime data ####################

configLastModified = 0
ontLastModified = 0
internalsLastModified = 0
configLastInode = 0
ontLastInode = 0
internalsLastInode = 0

config = {}                # Maps: $s->{$p}->[v1, v2, ... vn]

# Node metadata distilled for the pipeline is held in $nm.  It is
# a combination of several kinds of maps from subject to predicate 
# to one or more objects.
# The objects may be different kinds, depending on the predicate,
# but these data structures don't bother to keep track of which
# predicate uses which object type.  Instead, we generate all
# object types for all predicates.  The main data structure is $nm
# for "node metadata").
# But For ease of access the following variables point to various different
# slices of the $nm data structure.
#  For single-valued predicates:
#    my $nmv = $nm->{value};
#    my $value = $nmv->{$subject}->{$predicate};
#  For list-valued predicates:
#    my $nml = $nm->{list};
#    my $listRef = $nml->{$subject}->{$predicate};
#    my @list = @{$listRef};
#  For hash-valued predicates:
#    my $nmh = $nm->{hash};
#    my $hashRef = $nmh->{$subject}->{$predicate};
#    my $value = $hashRef->{$key};
#  For multi-valued predicates:
#    my $nmm = $nm->{multi};
#    my $hashRef = $nmm->{$subject}->{$predicate};
#      For list of unique values (for non-unique use {list} instead):
#    my @values = keys %{$hashRef};
#      To see if a particular value exists (each $value is mapped to 1):
#    if ($hashRef->{$value}) ...
# Since each predicate uses only one of these, we could obviously save
# memory if we kept track of which predicate holds which kind of object,
# and then only store that kind for that predicate.
nm = {}

##################  Constants for this server  ##################
ontologyPrefix = "http://purl.org/pipeline/ont#"  # Pipeline ont prefix

# 80 and 443 are the default ports for http and https:
if SERVER_PORT is not None and SERVER_PORT in {"80", "443"} :
   die(f"[ERROR] SERVER_PORT={SERVER_PORT} must not be set if it is the default for the scheme, because it will mess up IsCurrentWebServer tests.\n")
if not IsCurrentWebServer(SERVER_NAME, SERVER_PORT) :
   die(f"[ERROR] Non-local $SERVER_NAME:$SERVER_PORT {SERVER_NAME}:{SERVER_PORT}\n")
# die("[DUMP] Non-local $SERVER_NAME: {"+os.environ['SERVER_NAME']+"}\n")
serverName = "localhost"
# If "localhost" is not recognized current web server, then
# at least 127.0.0.1 should be.
if not IsCurrentWebServer(serverName, SERVER_PORT) :
    serverName = "127.0.0.1" 
if not IsCurrentWebServer(serverName, SERVER_PORT) :
    die(f"[ERROR] Not recognized as local: {serverName} SERVER_PORT: {SERVER_PORT}")
# $baseUri is the URI prefix that corresponds directly to DOCUMENT_ROOT.
# baseUri = CanonicalizeUri(f"http://127.0.0.1:{SERVER_PORT}");
baseUri = f"{SERVER_SCHEME}://{SERVER_NAME}"
if SERVER_PORT != '' :
    baseUri += f":{SERVER_PORT}"
# $baseUri will normally now be "http://localhost:5000" -- ready for use.
# url_normalize adds a trialing slash:
if f"{baseUri}/" != url_normalize(baseUri) :
    Die(f"[ERROR] Configuration error: baseURI/={baseUri}/\n does not match normalized baseUri={url_normalize(baseUri)}\n Is $SERVER_PORT={SERVER_PORT} set wrong?\n It should not be set if it is the default for this $SERVER_SCHEME={SERVER_SCHEME}")

baseUriPattern = re.escape(baseUri)
basePath = os.environ['DOCUMENT_ROOT']    # Synonym, for convenience
basePathPattern = re.escape(basePath)
nodeBaseUri = baseUri + "/node"     # Base for nodes
nodeBaseUriPattern = re.escape(nodeBaseUri)
nodeBasePath = basePath + "/node"
nodeBasePathPattern = re.escape(nodeBasePath)
lmCounterFile = basePath + "/lm/lmCounter.txt"
rdfsPrefix = "http://www.w3.org/2000/01/rdf-schema#"
# our $subClassOf = $rdfsPrefix . "subClassOf";
subClassOf = "rdfs:subClassOf"

# This $configFile will be used only if $RDF_PIPELINE_MASTER_URI is not set:
configFile = nodeBasePath + "/pipeline.ttl"
ontFile = basePath + "/ont/ont.n3"
internalsFile = basePath + "/ont/internals.n3"
tmpDir = basePath + "/tmp"

#### $nameType constants used by SaveLMs/LookupLMs:
#### TODO: Change to "use Const".
URI = 'URI'
FILE = 'FILE'

systemArgs = ['debug', 'debugStackDepth', 'callerUri', 'callerLM', 'method']

Warn(f'Starting with debug: {debug}\n')
Warn("********** NEW APACHE THREAD INSTANCE **********\n", DEBUG_DETAILS)

#### Hopefully this is not needed in python:
# my $hasHiResTime = &Time::HiRes::d_hires_stat()>0;
# $hasHiResTime || die;

#### Command-line testing is not implemented in the python version

##################### handler #######################
# handler will be called by apache2 to handle any request that has
# been specified in /etc/apache2/sites-enabled/000-default .
def handler(r):
    # my $r = shift || die;
    # base_url omits the query params
    thisUri = r.base_url
    oldThisUri = thisUri
    thisUri = CanonicalizeUri(thisUri)
    qp = r.args;
    args = {k: v[0] for k, v in qp.items()}
    global debug
    if 'debug' in args :
        debug = args['debug'] 
    #### Not implemented in python version:
    # # Allows symbolic $debug value:
    # $debug = eval $debug if defined($debug) && $debug =~ m/^\$\w+$/;
    global debugStackDepth
    debugStackDepth = 0
    if 'debugStackDepth' in args :
        debugStackDepth = args['debugStackDepth'] 
    # warn("="x30 . " handler " . "="x30 + "\n");
    Warn("="*30 + " handler " + "="*30 + "\n", DEBUG_DETAILS);
    Warn(f"handler debug level: {debug}\n", DEBUG_DETAILS);
    # Warn("" . `date`, DEBUG_DETAILS);
    Warn("" + os.popen('date').read(), DEBUG_DETAILS);
    # Warn("SERVER_NAME: $ENV{SERVER_NAME} serverName: $serverName\n", DEBUG_DETAILS);
    Warn("SERVER_NAME: " + SERVER_NAME + f" serverName: {serverName}\n", DEBUG_DETAILS);
    Warn(f"oldThisUri: {oldThisUri}\n", DEBUG_DETAILS);
    Warn(f"thisUri: {thisUri}\n", DEBUG_DETAILS);
    Warn(f"baseUri: {baseUri}\n", DEBUG_DETAILS);
    Warn(f"basePath: {basePath}\n", DEBUG_DETAILS);
    # Warn("DOCUMENT_ROOT: $ENV{DOCUMENT_ROOT}\n", DEBUG_DETAILS);
    Warn("DOCUMENT_ROOT: " + os.environ.get('DOCUMENT_ROOT', '') + "\n", DEBUG_DETAILS);
    # Set $RDF_PIPELINE_DEV_DIR and $PATH so that updaters will inherit them.
    # For some reason, in apache2/mod_perl it does not work to set this only once when the thread
    # starts.  $ENV{PATH}, at least, seems to be reset each time the handler
    # is called after the first time.  I don't know what happens in flask.
    global RDF_PIPELINE_DEV_DIR
    if RDF_PIPELINE_DEV_DIR is None :
        RDF_PIPELINE_DEV_DIR = os.environ.get('RDF_PIPELINE_DEV_DIR')
        if RDF_PIPELINE_DEV_DIR is None :
            # execute the set_env.sh script so we can get the variables in our env
            # RDF_PIPELINE_DEV_DIR = `. $script_dirname/set_env.sh ; echo -n \$RDF_PIPELINE_DEV_DIR`
            script = f'. "{script_dirname}/set_env.sh" ; echo -n \\$RDF_PIPELINE_DEV_DIR'
            Warn(f"RDF_PIPELINE_DEV_DIR script: {script}")
            RDF_PIPELINE_DEV_DIR = os.popen(script).read()
        if not os.path.isdir(RDF_PIPELINE_DEV_DIR) :
            die("[INTERNAL ERROR] RDF_PIPELINE_DEV_DIR is not set or not a dir: {RDF_PIPELINE_DEV_DIR}\n")
        os.environ['RDF_PIPELINE_DEV_DIR'] = RDF_PIPELINE_DEV_DIR
    # Warn(f"RDF_PIPELINE_DEV_DIR: {RDF_PIPELINE_DEV_DIR}")

    # Set PATH in env
    global PATH
    dirs = []
    if PATH is None :
        # To make sure that PATH is set correctly,
        # execute the set_env.sh script to set it.
        # If it was already set, this will cause no harm, because
        # it will only append to the path.
        # PATH = `. $script_dirname/set_env.sh ; echo -n \$PATH`
        script = f'. "{script_dirname}/set_env.sh" ; echo -n "$PATH"'
        Warn(f"PATH script: {script}")
        PATH = os.popen(script).read()
        # As a sanity check, make sure at least two elements of $PATH
        # are directories, and make sure it contains the tools dir:
        # dirs = filter(lambda f: os.path.isdir(f), PATH.split(os.pathsep))
        dirs = [d for d in PATH.split(os.pathsep) if os.path.isdir(d)]
        toolsDir = RDF_PIPELINE_DEV_DIR + "/tools"
        # Warn(f"dirs: {dirs}")
        # Warn(f"toolsDir: {toolsDir}")
        if len(dirs) < 2 or not (toolsDir in PATH) :
            die(f"[INTERNAL ERROR] PATH is not set properly: {PATH}\n")
        os.environ['PATH'] = PATH
    # Warn(f"PATH: {PATH}")

    # Flattened list of key/value pairs:
    argsList = [item for pair in args for item in pair]
    nArgs = len(argsList)
    Warn(f"Query string (elements {nArgs}): {argsList}\n", DEBUG_DETAILS);
    # Warn("-"*20 + "handler" + "-"*20 + "\n", DEBUG_DETAILS);
    ret = RealHandler(r, thisUri, args);
    Warn("RealHandler returned: {ret}\n", DEBUG_DETAILS);
    Warn("="*60 + "\n", DEBUG_DETAILS);
    return ret;

########## AbsUri ############
# Converts (possibly relative) URI to absolute URI, using $baseUri.
def AbsUri(uri):
    # From RFC 3986:
    #    scheme  = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
    #### TODO: change this to use the perl URI module:
    #### http://lwp.interglacial.com/ch04_04.htm
    # if ($uri !~ m/\A[a-zA-Z][a-zA-Z0-9\+\-\.]*\:/) {
    if not re.match(r'[a-zA-Z][a-zA-Z0-9\+\-\.]*\:', uri) :
            # Relative URI
            # $uri =~ s|\A\/||;       # Chop leading / if any
            if uri[0] == '/' :
                uri = uri[1:]
            uri = baseUri + "/" + uri
    return uri

########## UriToPath ############
# Converts (possibly relative) URI to absolute file path (if local)
# or returns "".   Extra parameters ($baseUri and $hostRoot) are ignored
# and globals $baseUriPattern and $basePath are used instead.
def UriToPath(uri):
    ### Ignore these parameters and use globals $baseUriPattern and $basePath:
    path = AbsUri(uri)
    #### TODO: Make this work for IPv6 addresses.
    #### TODO: Why are we only stripping port 80?
    # Get rid of superfluous port 80 before converting:
    path = re.sub(r'\A(http(s?)\:\/\/[^\/\:]+)\:80\/', r'\1\/', path)
    oldPath = path
    path = re.sub(r'\A' + baseUriPattern + r'\/', f"{basePath}/", path)
    Warn(f"UriToPath uri: {uri}")
    Warn(f"UriToPath oldPath: {oldPath}")
    Warn(f"UriToPath path: {path}")
    if oldPath != path :
        return path
    return ""

################ def IsLocalNode #################
# No longer needed.  Use IsCurrentWebServer instead.

################ def Mirror #################
# Conditionally GET content from a URL, saving to a given file.
# Return 1 iff the file was updated.
mirrorHeaders = {}
def Mirror(url, filepath):
    Warn(f"Mirror called with url={url} filepath={filepath}")
    headers = mirrorHeaders[url] if url in mirrorHeaders else {}
    Warn(f"  Old headers: {json.dumps(headers, indent=2)}")
    if not os.path.isfile(filepath) :
        # If the file got deleted, force an unconditional GET:
        Warn(f"  File is gone!  Clearing headers.")
        headers = {}
    req = urllib.request.Request(url, headers = headers)
    try:
        response = urllib.request.urlopen(req)
        Warn(f"  response.status={response.status}")
        Warn(f"  response.getheaders()={json.dumps(response.getheaders(), indent=2)}")
        if response.status == 200 :
            newHeaders = {}
            etag = response.getheader('ETag')
            if etag is not None :
                Warn(f"  Got ETag: {etag}")
                newHeaders['If-None-Match'] = etag
            lm = response.getheader('Last-Modified')
            if lm is not None :
                Warn(f"  Got Last-Modified: {lm}")
                newHeaders['If-Modified-Since'] = lm
            mirrorHeaders[url] = newHeaders
            content = response.read()
            MakeParentDirs(filepath)
            with open(filepath,"wb") as fp:
                fp.write(content)
            Warn(f"  wrote file: {filepath}")
            return 1
        else :
            Die(f"[ERROR] Mirror: GET return unknown status={response.status}")
    except urllib.error.HTTPError as e:
        # Oddly, urllib.request treats a 304 response as an exception,
        # which I think was a design mistake.
        if e.code == 304 :
            Warn(f"  304 Not modified.")
            return 0
        else :
            Warn(f"  Error: {e.code}")
            raise e
    # return content

########## MakeParentDirs ############
# Ensure that parent directories exist before creating this file.
# Optionally, directories that have already been created are remembered, so
# we won't waste time trying to create them again.
def MakeParentDirs(path):
    fDir, tail = os.path.split(path)
    if not os.path.isdir(fDir) :
        os.makedirs(fDir, exist_ok=True)

############### MTime #################
# Return the nanoseconds last modified time for the given file.
def MTime(path):
    mtime, inode = MTimeAndInode(path)
    return mtime

############### &MTimeAndInode #################
# Return the nanoseconds last modified time and inode for the given file.
def MTimeAndInode(path):
    s = os.stat(path)
    return s.st_mtime_ns, s.st_ino

############### LM Constants ##############
# An LM is derived from the (floating point) number of seconds since
# the epoch, followed by some counter digits that ensure that the LM
# is unique even if the clock did not change noticeably between calls.
#
# Example LM: 0123456789.123456000001
#             |        | |    ||    |
#             + seconds+ + ms ++ counter
#
# Zero-padded digits of seconds left of decimal point:
lmSecondsWidth = 10     
# Digits right of decimal point:
lmDecimalPlaces = 6     
# Number of digits in the LM counter:
lmCounterWidth = 6
# These are for convenience:
lmSecondsDPWidth = lmSecondsWidth + 1 + lmDecimalPlaces
nsPerSecond = 1000 * 1000 * 1000
lmNsPerTick = nsPerSecond
lmTicksPerSecond = 1
for _ in range(lmDecimalPlaces):
    lmNsPerTick //= 10
    lmTicksPerSecond *= 10
if lmNsPerTick == 0 :
    Die(f"Too many decimal places for nanosecond clock values in lmDecimalPlaces: '{lmDecimalPlaces}'")
lmCounterMax = 1
for _ in range(lmCounterWidth):
    lmCounterMax *= 10
lmCounterMax -= 1
if lmCounterMax < 9 :
    Die(f"Bad lmCounterMax ({lmCounterMax}) computed from lmCounterWidth: {lmCounterWidth}")

########## FormatTime ############
# Truncate nanoseconds time into milliseconds time 
# and turn it into a string.
# (This differs from the perl version, which expects
# a floating point time in seconds.)
# The string is padded with leading zeros for easy string comparison,
# ensuring that $a lt $b iff $a < $b.
# An empty string "" will be returned if the time is 0.
def FormatTime(timeNs):
    if not timeNs or timeNs == 0 :
        return ""
    # Enough digits to work through year 2286:
    # my $lm = sprintf("%010.6f", $time);
    timeMs = timeNs // lmNsPerTick
    sec, ms = divmod(timeMs, lmTicksPerSecond)
    lm = f"{sec:0{lmSecondsWidth}}.{ms:0{lmDecimalPlaces}}"
    # length($lm) == 10+1+6 or confess "Too many digits in time!";
    if len(lm) != lmSecondsWidth+1+lmDecimalPlaces :
        Die(f"FormatTime: Wrong number of digits in LM time: '{lm}'")
    return lm

########## FormatCounter ############
# Format a counter for use in an LM string.
# The counter becomes the lowest order digits.
# The string is padded with leading zeros for easy string comparison,
# ensuring that $a lt $b iff $a < $b.
def FormatCounter(counter):
    if counter is None :
        counter = 0
    lmCounterWidth = 6
    # my $sCounter = sprintf("%0$lmCounterWidth" . "d", $counter);
    sCounter = f"{counter:0{lmCounterWidth}}"
    if len(sCounter) > lmCounterWidth :
        Die(f"FormatCounter: Counter overflow! Need more than lmCounterWidth={lmCounterWidth} digits in counter!")
    return sCounter

########## TimeToLM ############
# Turn an int nanosecond time (and optional counter) into an LM string,
# for use in headers, etc.  The counter becomes the lowest order digits.
# The string is padded with leading zeros for easy string comparison,
# ensuring that $a lt $b iff $a < $b.
# An empty string "" will be returned if the timeNs is 0.
# As generated, these are monotonic.  But in general the system does
# not require LMs to be monotonic, because they could be checksums.
# The only guarantee that the system requires is that they change
# if a node output has changed.
def TimeToLM(timeNs, counter):
    if not timeNs :
        return "" 
    if counter is None :
        counter = 0
    return FormatTime(timeNs) + FormatCounter(counter)

############# TestLmGenerator ##############
def TestLmGenerator(n):
    oldLm = 0
    for _ in range(n):
        lm = GenerateNewLM(oldLm)
        if lm[-1] != '0' :
            raise ValueError("lm: "+lm)
        oldLm = lm

############# GenerateNewLM ##############
# Generate a new LM, based on the current time, that is guaranteed unique
# on this server even if this function is called faster than the 
# clock resolution.  Within the same thread
# it is guaranteed to increase monotonically (assuming the 
# clock increases monotonically).  This is done by
# appending a counter to the lower order digits of the current time.
# Even if the clock is not monotonic, it will still generate a different
# LM from the given oldLm, by incrementing the counter if the
# time is otherwise the same.
#
# Example LM: 0123456789.123456000001
#             |        | |    ||    |
#             + seconds+ + ms ++ counter
#
def GenerateNewLM(oldLm):
    oldTimeMs = 0
    oldCounter = -1     # Will be incremented before use 
    tNs = time.time_ns()
    tMsString = FormatTime(tNs)     
    # tMsString looks like: "0123456789.123456" (i.e., no counter)
    tMs = tNs // lmNsPerTick
    if oldLm :
        # oldLm looks like: "0123456789.123456000001"
        if len(oldLm) != lmSecondsDPWidth+lmCounterWidth :
            Die(f"GenerateNewLM: corrupt oldLm: '{oldLm}'")
        # Extract the old ms time as string, i.e., chop off the counter.
        # oldMsString will look like: "0123456789.123456"
        oldMsString = oldLm[0 : lmSecondsDPWidth]
        # Still the same time?   If so, grab the old counter.
        if tMsString == oldMsString :
            oldCounterString = oldLm[lmSecondsDPWidth : ]
            oldCounter = int(oldCounterString)
    counterString = FormatCounter(oldCounter+1)
    lm = tMsString + counterString
    if len(lm) != lmSecondsDPWidth+lmCounterWidth :
        Die(f"GenerateNewLM: Internal error in generating lm: '{lm}'")
    return lm

################ IsExecutable #################
def IsExecutable(f):
    return os.access(f, os.X_OK)

commentOut = '''
############# FileNodeRunUpdater ##############
# Run the updater.
# If there is no updater (i.e., static state) then we must generate
# an LM from the state.
def FileNodeRunUpdater(nm, thisUri, updater, state, thisInputs, thisParameters, 
        oldThisLM, callerUri, callerLM):
    Warn(f"FileNodeRunUpdater(nm, {thisUri}, {updater}, {state}, ...) called.\n", DEBUG_DETAILS)
    if not updater :
        # TODO: Make a way to retain as many digits of MTime as possible
        # when dealing with a static file.
        return TimeToLM(MTime(state), -1)
    state || die;
    state = NodeAbsPath(state)
    updater = &NodeAbsPath(updater);
    Warn(f"Abs state: {state}  Abs updater: {updater}\n", $DEBUG_DETAILS);
    # TODO: Move this warning to when the metadata is loaded?
    if not IsExecutable(updater) :
        die(f"ERROR: {thisUri} updater {updater} is not executable by web server!")
    # The FileNode updater args are local filenames for all
    # inputs and parameters.
    **** STOPPED HERE ****
    my $inputFiles = join(" ", map {quotemeta($_)} 
        @{$nm->{list}->{$thisUri}->{inputCaches}});
    &Warn("inputFiles: $inputFiles\n", $DEBUG_DETAILS);
    my $parameterFiles = join(" ", map {quotemeta($_)} 
        @{$nm->{list}->{$thisUri}->{parameterCaches}});
    &Warn("parameterFiles: $parameterFiles\n", $DEBUG_DETAILS);
    my $ipFiles = "$inputFiles $parameterFiles";
    #### TODO: Move this code out of this function and pass $latestQuery
    #### as a parameter to FileNodeRunUpdater.
    #### TODO QUERY:
    my $thisVHash = $nm->{value}->{$thisUri} || die;
    my $parametersFile = $thisVHash->{parametersFile} || die;
    my ($lm, $latestQuery, %requesterQueries) = 
        &LookupLMs($FILE, $parametersFile);
    $lm = $lm;				# Avoid unused var warning
    my $qLatestQuery = quotemeta($latestQuery);
    my $exportqs = "export QUERY_STRING=$qLatestQuery";
    $exportqs = &ConstructQueryStringExports($latestQuery) . " $exportqs";
    # my $qss = quotemeta(&BuildQueryString(%requesterQueries));
    my $qss = quotemeta(join(" ", sort values %requesterQueries));
    my $exportqss = "export QUERY_STRINGS=$qss";
    ####
    my $stderr = $nm->{value}->{$thisUri}->{stderr};
    # Make sure parent dirs exist for $stderr and $state:
    &MakeParentDirs($stderr, $state);
    # Ensure no unsafe chars before invoking $cmd:
    my $qThisUri = quotemeta($thisUri);
    my $qState = quotemeta($state);
    my $qUpdater = quotemeta($updater);
    my $qStderr = quotemeta($stderr);
    my $useStdout = 0;
    my $stateOriginal = $nm->{value}->{$thisUri}->{stateOriginal} || "";
    &Warn("stateOriginal: $stateOriginal\n", $DEBUG_DETAILS);
    $useStdout = 1 if $updater && !$stateOriginal;
    die "[INTERNAL ERROR] RDF_PIPELINE_DEV_DIR not set in environment! "
        if !$ENV{RDF_PIPELINE_DEV_DIR};
    my $qToolsDir = quotemeta("$ENV{RDF_PIPELINE_DEV_DIR}/tools");
    die "[INTERNAL ERROR] PATH not set properly: $ENV{PATH} "
        if $ENV{PATH} !~ m/$qToolsDir/;
    &Warn("ENV{PATH}: $ENV{PATH}\n", $DEBUG_DETAILS);
    &Warn("ENV{RDF_PIPELINE_DEV_DIR}: $ENV{RDF_PIPELINE_DEV_DIR}\n", $DEBUG_DETAILS);
    my $qPath = quotemeta($ENV{PATH}) || die;
    my $cmd = "( cd '$nodeBasePath' ; export THIS_URI=$qThisUri ; export PATH=$qPath ; $qUpdater $qState $ipFiles > $qStderr 2>&1 )";
    $cmd =    "( cd '$nodeBasePath' ; export THIS_URI=$qThisUri ; export PATH=$qPath ; $qUpdater         $ipFiles > $qState 2> $qStderr )"
        if $useStdout;
    #### TODO QUERY:
    $cmd = "( cd '$nodeBasePath' ; export THIS_URI=$qThisUri ; export PATH=$qPath ; $exportqs ; $exportqss ; $qUpdater $qState $ipFiles > $qStderr 2>&1 )";
    $cmd = "( cd '$nodeBasePath' ; export THIS_URI=$qThisUri ; export PATH=$qPath ; $exportqs ; $exportqss ; $qUpdater         $ipFiles > $qState 2> $qStderr )"
        if $useStdout;
    ####
    &Warn("cmd: $cmd\n", $DEBUG_DETAILS);
    my $result = (system($cmd) >> 8);
    my $saveError = $?;
    &Warn("FileNodeRunUpdater: Updater returned " . ($result ? "error code:" : "success:") . " $result.\n", $DEBUG_DETAILS);
    if (-s $stderr) {
        &Warn("FileNodeRunUpdater: Updater stderr" . ($useStdout ? "" : " and stdout") . ":\n[[\n", $DEBUG_DETAILS);
        &Warn(&ReadFile("<$stderr"), $DEBUG_DETAILS);
        &Warn("]]\n", $DEBUG_DETAILS);
        }
    # unlink $stderr;
    if ($result) {
        &Warn("FileNodeRunUpdater: UPDATER ERROR: $saveError\n");
        return "";
        }
    my $newLM = &GenerateNewLM();
    &Warn("FileNodeRunUpdater returning newLM: $newLM\n", $DEBUG_DETAILS);
    return $newLM;
    }

############# RegisterWrappers ##############
def RegisterWrappers(nm):
    # TODO: Wrapper registration should be done differently so that the
    # framework can verify that all required properties have been set for
    # a new node type, and issue a warning if not.  Somehow, the framework
    # needs to know what node types are being registered.
    FileNodeRegister(nm)
    ExampleHtmlNodeRegister(nm)
    GraphNodeRegister(nm)

############# FileNodeRegister ##############
def FileNodeRegister(nm):
    nm["value"]["FileNode"] = {}
    nm["value"]["FileNode"]["fSerializer"] = ""
    nm["value"]["FileNode"]["fDeserializer"] = ""
    nm["value"]["FileNode"]["fUriToNativeName"] = UriToPath
    nm["value"]["FileNode"]["fRunUpdater"] = FileNodeRunUpdater
    nm["value"]["FileNode"]["fRunParametersFilter"] = FileNodeRunParametersFilter
    nm["value"]["FileNode"]["fExists"] = FileExists
    nm["value"]["FileNode"]["defaultContentType"] = "text/plain"

    *** STOPPED HERE ***
'''

############# ExampleHtmlNodeRegister ##############
def ExampleHtmlNodeRegister(nm):
    Warn("[WARNING] ExampleHtmlNodeRegister not implemented")

############# GraphNodeRegister ##############
def GraphNodeRegister(nm):
    Warn("[WARNING] GraphNodeRegister not implemented")

##################### RealHandler #######################
def RealHandler(r, thisUri, args):
    # $debug = ($r && $r->uri =~ m/c\Z/);
    # $r->content_type('text/plain') if $debug && !$test;
    d = os.popen('date').read()
    Warn(f"RealHandler: {thisUri} {d}", DEBUG_DETAILS);
    if 0 and debug :
        Warn("Environment variables:\n", DEBUG_DETAILS);
        for k in sorted(os.environ.keys()) :
            Warn(f"  {k} = " + os.environ[k] + "\n", DEBUG_DETAILS);
        Warn("\n", DEBUG_DETAILS);

    # my $args = $r->args() || "";
    args = r.args
    Warn(f"Query string args unparsed: {r.query_string}\n", DEBUG_DETAILS);
    Warn("Query string args parsed:\n", DEBUG_DETAILS);
    # foreach my $k (sort keys %args) {
    for k in sorted(args.keys()) :
        #### TODO: this line doesn't make sense, because k will
        #### never be None anyway:
        dk = "(undef)" if k is None else k
        v = args[k];
        dv = "(undef)" if v is None else v
        Warn(f"  {dk}={dv}\n", DEBUG_DETAILS);

    masterUri = os.environ.get('RDF_PIPELINE_MASTER_URI', '')
    masterUri = CanonicalizeUri(masterUri)
    if masterUri :
        if IsCurrentWebServer(masterUri) :
            # Master is on the same server.  Do a direct file access instead 
            # of an HTTP request, to avoid infinite recursion of HTTP requests. 
            global configFile
            configFile = UriToPath(masterUri)
            Warn(f"Using LOCAL masterUri: {masterUri} with configFile: {configFile}:\n", DEBUG_DETAILS);
            # Since $masterUri is local, it does not need to be mirrored:
            masterUri = "";
        else :
            # Master is on a differnet server.
            # This is where it will be cached when mirrored:
            configFile = f"{basePath}/cache/pipeline_master.ttl";

    Warn(f"RealHandler masterUri: {masterUri}");
    Warn(f"RealHandler configFile: {configFile}");
    ret = "Dummy RealHandler Result"
    return ret
stoppedHere = '''============== BEGIN COMMENT
# **** STOPPED HERE ****

    # Default is 3 seconds
    global throttleSeconds
    throttleSeconds = int(os.environ.get('RDF_PIPELINE_MASTER_DOWNLOAD_THROTTLE_SECONDS', '3'))
    global lastMasterMirrorTime     # Time last mirroring finished
    mirrorWasUpdated = 0
    if (masterUri) :
      # Master is on a different server.  Do we need to re-mirror it?
      if (lastMasterMirrorTime and throttleSeconds
            and time.time() < lastMasterMirrorTime + throttleSeconds
            and os.path.exists(configFile)) :
                # Still fresh, no need to mirror it again.  Nothing to do.
                pass
      else :
        # Refresh the master by mirroring again.
        Warn(f"[INFO] Mirroring {masterUri} to {configFile}\n", DEBUG_DETAILS)
        MakeParentDirs(configFile)
        mirrorWasUpdated = Mirror(masterUri, configFile)
        # Set $lastMasterMirrorTime *after* mirroring, so that $throttleSeconds 
        # will be the minimum time from *after* the last mirror to *before* 
        # the next mirror.  I.e., prevent it from including the time spent 
        # doing the mirroring, in case the mirroring takes a long time.
        lastMasterMirrorTime = time.time();

    # At this point $configFile should exist, either from mirroring
    # or from being local.  So now we should be able to just rely on the local
    # file modification date to determine whether to reload the
    # pipeline definition.  However, we also check $mirrorWasUpdated in case
    # it was updated from mirroring faster than the file modification
    # time can detect.
    cmtime, cinode = MTimeAndInode(configFile)
    omtime, oinode = MTimeAndInode(ontFile)
    imtime, iinode = MTimeAndInode(internalsFile)
    cmtime or Die(f"[ERROR] File not found: {configFile}\n";
    omtime or Die(f"[ERROR] File not found: {ontFile}\n";
    imtime or Die(f"[ERROR] File not found: {internalsFile}\n";

    # Reload the pipeline definition?
    if ( mirrorWasUpdated
            or configLastModified != cmtime
            or ontLastModified != omtime
            or internalsLastModified != imtime
            or configLastInode != cinode
            or ontLastInode != oinode
            or internalsLastInode != iinode) {
        # Initialize node metadata:
        nm = {"value": {}, "list": {}, "hash": {}, "multi": {}};
        **** STOPPED HERE ***
        &RegisterWrappers($nm);
        &Warn("--------- NodeMetadata after RegisterWrappers -------\n", $DEBUG_DETAILS); 
        &PrintNodeMetadata($nm) if $debug;
        # Reload config file.
        &Warn("Reloading config file: $configFile\n", $DEBUG_DETAILS);
        $configLastModified = $cmtime;
        $ontLastModified = $omtime;
        $internalsLastModified = $imtime;
        $configLastInode = $cinode;
        $ontLastInode = $oinode;
        $internalsLastInode = $iinode;
        &LoadNodeMetadata($nm, $ontFile, $internalsFile, $configFile);
        &PrintNodeMetadata($nm) if $debug;

        # &Warn("Got here!\n", $DEBUG_DETAILS); 
        # return Apache2::Const::OK;
        # %config || return Apache2::Const::SERVER_ERROR;
        }
    ##### BEGIN updaters/translators library
    # Intercept 'updaters' request and forward to the updaters/translators libary.
    # TODO: Change this from using the path /node/updaters to
    # something that cannot clash with a node name.
    if ($r->uri() eq "/node/updaters") {
        my $startTime = Time::HiRes::time();
        my $updatersUri = "https://github.com/rdf-pipeline/framework/tree/master/tools/updaters";
        $r->headers_out->set('Location' => $updatersUri); 
        &LogDeltaTimingData("HandleHttpEvent", $thisUri, $startTime, 1);
        return Apache2::Const::REDIRECT;
        }
    ##### END updaters/translators library
    ##### BEGIN pedit
    # Intercept admin request and return the pipeline editor.
    # TODO: Instead of using the path /node/admin for this,
    # change the apache config to make it use /admin ,
    # perhaps using <LocationMatch ...>:
    # http://httpd.apache.org/docs/current/mod/core.html#locationmatch
    if ($r->uri() eq "/node/admin") {
        my $method = $r->method;
        return Apache2::Const::HTTP_METHOD_NOT_ALLOWED if $method ne 'GET' && $method ne 'HEAD';
        my $startTime = Time::HiRes::time();
        $r->content_type("text/html");
        my $qToolsDir = quotemeta("$ENV{RDF_PIPELINE_DEV_DIR}/tools");
        # TODO: provide the pipeline definition as input to show-pipeline.perl:
        my $content = `$qToolsDir/pedit/show-pipeline.perl`;
        my $size = length($content);
        $r->set_content_length($size) if defined($size);
        if($r->header_only) {
            &LogDeltaTimingData("HandleHttpEvent", $thisUri, $startTime, 1);
            return Apache2::Const::OK;
            }
        $r->print($content);
        &LogDeltaTimingData("HandleHttpEvent", $thisUri, $startTime, 1);
        return Apache2::Const::OK;
        }
    ##### END pedit
    my $subtype = $nm->{value}->{$thisUri}->{nodeType} || "";
    &Warn("NOTICE: $thisUri is not a Node.\n", $DEBUG_DETAILS) if !$subtype;
    &Warn("thisUri: $thisUri subtype: $subtype\n", $DEBUG_DETAILS);
    # Allow non-node files in the www/node/ dir to be served normally:
    return Apache2::Const::DECLINED if !$subtype;
    # return Apache2::Const::NOT_FOUND if !$subtype;
    return &HandleHttpEvent($nm, $r, $thisUri, %args);
    }
'''

#########################################################
######################### Main ##########################
#########################################################

# TODO: Set up config files as recommended in
# https://flask.palletsprojects.com/en/1.1.x/config/

app = Flask(__name__)

# defining a route
@app.route("/", methods=['GET', 'POST', 'PUT']) # decorator
def home(): # route handler function
    # returning a response
    # return render_template('index.html', name = 'John')
    bu = urlparse(request.base_url)
    host = bu.hostname
    WarnLine("host: {" + host + "}")
    WarnLine("LocalIps: " +  " ".join(LocalIps()))
    sp = SERVER_PORT
    WarnLine("IsCurrentWebServer(127.0.0.1): " + str(IsCurrentWebServer("127.0.0.1", sp)))
    WarnLine("IsCurrentWebServer(192.168.90.152): " + str(IsCurrentWebServer("192.168.90.152", sp)))
    WarnLine("IsCurrentWebServer(10.8.0.54): " + str(IsCurrentWebServer("10.8.0.54", sp)))
    WarnLine("IsCurrentWebServer(localhost): " + str(IsCurrentWebServer("localhost", sp)))
    WarnLine("IsCurrentWebServer(dbooth-t470p): " + str(IsCurrentWebServer("dbooth-t470p", sp)))
    WarnLine("IsCurrentWebServer(dbooth-t470pxxx): " + str(IsCurrentWebServer("dbooth-t470pxxx", sp)))
    Warn("Calling handler...")
    ret = handler(request)
    Warn("handler returned: " + ret)
    Warn("request.server: " + str(request.server))
    return render_template('index.html', name = " ".join(systemArgs))
    # return render_template('index.html', name = reprlib.repr(thisHost))
    # return render_template('index.html', name = 'Wow')

# run the application
if __name__ == "__main__" :
    app.run(host=SERVER_NAME, port=SERVER_PORT, debug = True)

