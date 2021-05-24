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
from flask import Flask, render_template, request
from urllib.parse import urlparse
import os
import sys
import inspect
import time
import reprlib
import socket
import functools
from urllib.parse import urlparse, urlunparse
from url_normalize import url_normalize
import re
import netifaces

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
    WarnLine("LocalIps: " + " ".join(LocalIps._localIps))
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
# However, it could cause a problem if an additional (different) web server
# is running on a different port of that IP, and only listening
# to that IP.
# Results are cached for fast repeated lookup.
@functools.lru_cache(maxsize=None)
def IsCurrentWebServer(host):
    try:
        #### TODO: is there an IPv6 localhost convention that also needs to be checked?
        ip = socket.gethostbyname(host)
        localIps = LocalIps()
        if ip in localIps :
            return True
        else: return False
    except OSError as error:
        # As a sanity check, make sure we can get the localhost IP.
        # If not, re-throw the original exception because we cannot run:
        try:
            localhostIp = socket.gethostbyname('localhost')
        except OSError:
            raise error
        # Inability to resolve a given host is non-fatal.  We consider
        # the host non-local:
        return False

################ CanonicalizeUri #################
# Canonicalize the given URI:  If it is an absolute local http URI,
# then canonicalize it to localhost or 127.0.0.1 .
# Other URIs are passed through unchanged.
# The reason for canonicalizing only node URIs on this host is because
# the RDF Popeline Framework will be handling requests for them, so
# it needs to be able to distinguish them from foreign URIs, both
# to avoid an infinite recursion of HTTP requests and to lookup
# metadata based on the URI.  If the URI were a synonym, such as
# http://127.0.0.1/node/foo instead of http://localhost/node/foo ,
# then the metadata lookup would fail to find the metadata.
canonicalizedUriCache = {}
def CanonicalizeUri(oldUri):
    global canonicalizedUriCache
    if oldUri in canonicalizedUriCache :
        return canonicalizedUriCache[oldUri]
    oldParsed = urlparse(oldUri)
    netloc = oldParsed.netloc
    if not IsCurrentWebServer(oldParsed.netloc) :
        return oldUri
    # Strip off the port if there is one:
    host = netloc
    colonPort = ''
    iColon = netloc.find(":")
    if iColon >= 0 :
        host = netloc[0:iColon]
        colonPort = netloc[iColon:]
    # Prefer localhost over 127.0.0.1
    # print(f'iColon {iColon} host {host} colonPort {colonPort}')
    localUri = oldUri
    if host == '127.0.0.1' :
        if IsCurrentWebServer('localhost') :
            netloc = 'localhost' + colonPort
            localUri = urlunparse(oldParsed._replace(netloc=netloc))
    # Finally canonicalize it:
    cu = url_normalize(localUri)
    # url_normalize adds a slash if needed, but we don't want it.
    # TODO: Figure out the impact of removing the final slash.
    if localUri[-1] != '/' and cu[-1] == '/' :
        cu = cu[0:-1]
    canonicalizedUriCache[oldUri] = cu
    return cu

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
    if level is not None and debug < level :
        return 1
    maxRecursion = 30
    # depth = debugStackDepth + &CallStackDepth() -2;
    depth = debugStackDepth + len(inspect.stack(0)) - debugStackDepthOffset
    if depth >= maxRecursion :
        raise RecursionError(f"PANIC!!!  Deep recursion > {maxRecursion}! debug {debug} \n Maybe a cycle in the pipeline graph?\n")
    indent = depth *2
    # Additional indent like &Warn("  One\nTwo\n") will be applied to
    # all lines in the given string also, producing:
    #     One
    #     Two
    moreSpaces = "";
    # $moreSpaces = $1 if $msg =~ s/^(\s+)//;
    # findall_sub(pattern, repl, string, count=0, flags=0):
    msg, matches = findall_sub(r'^(\s+)', '', msg)
    if (matches) :
        # $msg =~ s/^/$spaces/mg;
        moreSpaces = matches.group(1)
    spaces = (" " * indent) + moreSpaces
    msg = re.sub(r'^', spaces, msg, flags=re.MULTILINE)
    PrintLog(msg)
    if debug is None :
        sys.stderr.write("debug not defined!\n") 
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

# Get the current working directory
script_dirname = os.getcwd()

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
debug = os.getenv('RDF_PIPELINE_DEBUG', DEBUG_CHANGES)
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

# Node Metadata hash maps for mapping from subject
# to predicate to single value ($nmv), list ($nml) or hashmap ($nmh).
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
nm = {}

##################  Constants for this server  ##################
ontologyPrefix = "http://purl.org/pipeline/ont#"  # Pipeline ont prefix

def SetEnvDefault(yourDict, yourKey, defaultValue):
    yourDict[yourKey] = yourDict.get(yourKey, defaultValue)

SetEnvDefault(os.environ, 'DOCUMENT_ROOT', "/var/www")
### TODO: Set $baseUri properly.  Needs port?
SetEnvDefault(os.environ, 'SERVER_NAME', "localhost")
SetEnvDefault(os.environ, 'SERVER_PORT', "5000")
thisHost = os.environ['SERVER_NAME'] + ':' + os.environ['SERVER_PORT']
if not IsCurrentWebServer(os.environ['SERVER_NAME']) :
   die(f"[ERROR] Non-local $SERVER_NAME: {os.environ['SERVER_NAME']}\n")
# die("[DUMP] Non-local $SERVER_NAME: {"+os.environ['SERVER_NAME']+"}\n")
serverName = "localhost"
# If "localhost" is not recognized as local, then
# at least 127.0.0.1 should be.
if not IsCurrentWebServer(serverName) :
    serverName = "127.0.0.1" 
if not IsCurrentWebServer(serverName) :
    die("[ERROR] Not recognized as local: {serverName}")
# $baseUri is the URI prefix that corresponds directly to DOCUMENT_ROOT.
baseUri = CanonicalizeUri("http://127.0.0.1:$ENV{SERVER_PORT}");
# $baseUri will normally now be "http://localhost" -- ready for use.

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

strin = '''============== BEGIN COMMENT
# **** STOPPED HERE ****
################ CanonicalizeUri #################
# Canonicalize the given URI:  If it is an absolute local http URI,
# then canonicalize it to localhost or 127.0.0.1 .
# Other URIs are passed through unchanged.
# The reason for canonicalizing only node URIs on this web server is because
# the RDF Popeline Framework will be handling requests for them, so
# it needs to be able to distinguish them from foreign URIs, both
# to avoid an infinite recursion of HTTP requests and to lookup
# metadata based on the URI.  If the URI were a synonym, such as
# http://127.0.0.1/node/foo instead of http://localhost/node/foo ,
# then the metadata lookup would fail to find the metadata.
def CanonicalizeUri(oldUri):
    my $u = URI->new($oldUri);
    defined($u) || confess "[ERROR] Unable to parse URI: $oldUri ";
    # $u = URI->new($u->canonical);
    # http: or https:  URI?
    my $uScheme = $u->scheme;
    return $oldUri if !$uScheme;
    # defined($uScheme) || confess "[ERROR] Undefined scheme from URI: $oldUri ";
    return $oldUri if $uScheme !~ m/^http(s?)$/;
    # Local?
    my $host = $u->host;
    return $oldUri if !&IsCurrentWebServer($host);
    $host = "localhost";
    # Use 127.0.0.1 if localhost is not known:
    $host = "127.0.0.1" if !&IsCurrentWebServer($host);
    $host || die "$0: [ERROR] $host is not recognized as a local address ";
    # At this point we know it is a local http URI.
    # Canonicalize the URI.
    # It seems silly to parse the URI again, but I was unable to find
    # a perl module that would parse an http URI into all of its components
    # in such a way that it could be put back together while changing
    # only $scheme and $auth..
    my $uPort = $u->port;
    my ($scheme, $auth, $path, $query, $frag) = uri_split($oldUri);
    # $auth consists of: [ userinfo "@" ] host [ ":" port ]
    $auth = $host;
    $auth .= ":$uPort" if $uPort && $uPort != $u->default_port;
    $scheme = "http";
    my $newUri = uri_join($scheme, $auth, $path, $query, $frag);
    return $newUri;
    }

##################### handler #######################
# handler will be called by apache2 to handle any request that has
# been specified in /etc/apache2/sites-enabled/000-default .
def handler(r):
    {
    # my $r = shift || die;
    # base_url omits the query params
    thisUri = request.base_url
    oldThisUri = thisUri
    $thisUri = &CanonicalizeUri($thisUri);
    my $args = $r->args() || "";
    my %args = &ParseQueryString($args);
    $debug = $args{debug} if exists($args{debug});
    # Allows symbolic $debug value:
    $debug = eval $debug if defined($debug) && $debug =~ m/^\$\w+$/;
    $debugStackDepth = $args{debugStackDepth} || 0;
    # warn("="x30 . " handler " . "="x30 . "\n");
    &Warn("="x30 . " handler " . "="x30 . "\n", $DEBUG_DETAILS);
    &Warn("handler debug level: $debug\n", $DEBUG_DETAILS);
    &Warn("" . `date`, $DEBUG_DETAILS);
    &Warn("SERVER_NAME: $ENV{SERVER_NAME} serverName: $serverName\n", $DEBUG_DETAILS);
    &Warn("oldThisUri: $oldThisUri\n", $DEBUG_DETAILS);
    &Warn("thisUri: $thisUri\n", $DEBUG_DETAILS);
    &Warn("baseUri: $baseUri\n", $DEBUG_DETAILS);
    &Warn("basePath: $basePath\n", $DEBUG_DETAILS);
    &Warn("DOCUMENT_ROOT: $ENV{DOCUMENT_ROOT}\n", $DEBUG_DETAILS);
    # Set $RDF_PIPELINE_DEV_DIR and $PATH so that updaters will inherit them.
    # For some reason, it does not work to set this only once when the thread
    # starts.  $ENV{PATH}, at least, seems to be reset each time the handler
    # is called after the first time.
    if (!$ENV{RDF_PIPELINE_DEV_DIR}) {
            # execute set_env script so we can get the variables in our env
            my $both = `. $script_dirname/../../../set_env.sh ; echo \$PATH \$RDF_PIPELINE_DEV_DIR`;
            chomp $both;
            my ($path, $dev, $extra) = split(/ /, $both);
            die "[ERROR] \$PATH or \$RDF_PIPELINE_DEV_DIR contains a space "
                    if $extra;
            die "[ERROR] Failed to parse PATH and RDF_PIPELINE_DEV_DIR from {$both} "
                    if !$path || !$dev;
            $ENV{PATH} = $path;
            $ENV{RDF_PIPELINE_DEV_DIR} = $dev;
            }
    die "[INTERNAL ERROR] RDF_PIPELINE_DEV_DIR not set in environment! "
            if !$ENV{RDF_PIPELINE_DEV_DIR};
    my $qToolsDir = quotemeta("$ENV{RDF_PIPELINE_DEV_DIR}/tools");
    die "[INTERNAL ERROR] PATH not set properly: $ENV{PATH} "
            if $ENV{PATH} !~ m/$qToolsDir/;
    my @args = %args;
    my $nArgs = scalar(@args);
    &Warn("Query string (elements $nArgs): $args\n", $DEBUG_DETAILS);
    # &Warn("-"x20 . "handler" . "-"x20 . "\n", $DEBUG_DETAILS);
    # **** STOPPED HERE ****
    my $ret = &RealHandler($r, $thisUri, %args);
    &Warn("RealHandler returned: $ret\n", $DEBUG_DETAILS);
    &Warn("="x60 . "\n", $DEBUG_DETAILS);
    return $ret;
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
    WarnLine("IsCurrentWebServer(127.0.0.1): " + str(IsCurrentWebServer("127.0.0.1")))
    WarnLine("IsCurrentWebServer(192.168.90.152): " + str(IsCurrentWebServer("192.168.90.152")))
    WarnLine("IsCurrentWebServer(10.8.0.54): " + str(IsCurrentWebServer("10.8.0.54")))
    WarnLine("IsCurrentWebServer(localhost): " + str(IsCurrentWebServer("localhost")))
    WarnLine("IsCurrentWebServer(dbooth-t470p): " + str(IsCurrentWebServer("dbooth-t470p")))
    WarnLine("IsCurrentWebServer(dbooth-t470pxxx): " + str(IsCurrentWebServer("dbooth-t470pxxx")))
    return render_template('index.html', name = " ".join(systemArgs))
    # return render_template('index.html', name = reprlib.repr(thisHost))
    # return render_template('index.html', name = 'Wow')

app.run(host=os.environ['SERVER_NAME'], port=os.environ['SERVER_PORT'], debug = True)

