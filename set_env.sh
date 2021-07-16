#! /bin/sh

# This script sets the environment variables needed for testing the
# RDF Pipeline Framework.  It should be customized for your
# installation.  The following env vars are exported:
#
#       RDF_PIPELINE_DEV_DIR
#       PERL5LIB
#       PATH
#       DOCUMENT_ROOT
#
# Although this script is for the python version of the RDF Pipeline
# Framework, perl scripts are still used for testing.

# These will be used if the above variables are not already set:
DEFAULT_RDF_PIPELINE_DEV_DIR=/home/dbooth/rdf-pipeline/trunk
DEFAULT_PERL5LIB=$default_RDF_PIPELINE_DEV_DIR/RDF-Pipeline/lib
DEFAULT_DOCUMENT_ROOT=/tmp/www

# Helper function to add dirs to a PATH, leaving out redundancies
appendPaths() { 
    # use as: export PATH="$(appendPaths "$PATH" "dir1" "dir2")
    # start at the end:
    #  - join all arguments with :,
    #  - split the result on :,
    #  - pick out non-empty elements which haven't been seen and which are directories,
    #  - join with :,
    #  - print
    perl -le 'print join ":", grep /\w/ && !$seen{$_}++ && -d $_, split ":", join ":", @ARGV;' "$@"
}

# Get the RDF pipeline root install directory.
# Other directories are relative to this.
if [ -z "$RDF_PIPELINE_DEV_DIR" ]; then
       RDF_PIPELINE_DEV_DIR="$DEFAULT_RDF_PIPELINE_DEV_DIR"
       export RDF_PIPELINE_DEV_DIR
   fi

# Perl library path: add RDF Pipeline perl lib to it.
RDF_PIPELINE_PERL_PATH="${RDF_PIPELINE_DEV_DIR}/RDF-Pipeline/lib"
export PERL5LIB=$(appendPaths "${PERL5LIB}:${RDF_PIPELINE_PERL_PATH}" )

# Add test utilities to $PATH:
export PATH=$(appendPaths "$PATH:$RDF_PIPELINE_DEV_DIR/RDF-Pipeline/t" )
export PATH=$(appendPaths "$PATH:$RDF_PIPELINE_DEV_DIR/RDF-Pipeline/t/helpers" )

# Add tools utilities to $PATH:
export PATH=$(appendPaths "$PATH:$RDF_PIPELINE_DEV_DIR/tools" )

# Add generic sparql utilities to path (initially sesame,
# but eventually should become generic):
export PATH=$(appendPaths "$PATH:$RDF_PIPELINE_DEV_DIR/tools/gsparql/scripts/sesame2_6" )

# flask DOCUMENT_ROOT
if [ -z "$DOCUMENT_ROOT" ]; then
       DOCUMENT_ROOT="$DEFAULT_DOCUMENT_ROOT"
       export DOCUMENT_ROOT
   fi

