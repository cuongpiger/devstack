#!/usr/bin/env bash

# Print the commands being run so that we can see the command that triggers
# an error.  It is also useful for following along as the install occurs.
set -o xtrace

# Make sure custom grep options don't get in the way
unset GREP_OPTIONS

# We also have to unset other variables that might impact LC_ALL
# taking effect.
unset LANG
unset LANGUAGE
LC_ALL=en_US.utf8
export LC_ALL

# Clear all OpenStack related envvars
unset `env | grep -E '^OS_' | cut -d = -f 1`

# Make sure umask is sane
umask 022

# Not all distros have sbin in PATH for regular users.
# osc will normally be installed at /usr/local/bin/openstack so ensure
# /usr/local/bin is also in the path
PATH=$PATH:/usr/local/bin:/usr/local/sbin:/usr/sbin:/sbin
echo "[DEBUG][stack] The PATH is: $PATH"

# Keep track of the DevStack directory
TOP_DIR=$(cd $(dirname "$0") && pwd)
echo "[DEBUG][stack] The TOP_DIR is: $TOP_DIR"

# Check for uninitialized variables, a big cause of bugs
NOUNSET=${NOUNSET:-}
if [[ -n "$NOUNSET" ]]; then
    set -o nounset
fi
echo "[DEBUG][stack] The NOUNSET is: $NOUNSET"

# Set start of devstack timestamp
DEVSTACK_START_TIME=$(date +%s)
echo "[DEBUG][stack] The DEVSTACK_START_TIME is: $DEVSTACK_START_TIME"

# Clean up last environment var cache
if [[ -r $TOP_DIR/.stackenv ]]; then
    rm $TOP_DIR/.stackenv
fi

# ``stack.sh`` keeps the list of ``deb`` and ``rpm`` dependencies, config
# templates and other useful files in the ``files`` subdirectory
FILES=$TOP_DIR/files
if [ ! -d $FILES ]; then
    set +o xtrace
    echo "missing devstack/files"
    exit 1
fi

# ``stack.sh`` keeps function libraries here
# Make sure ``$TOP_DIR/inc`` directory is present
if [ ! -d $TOP_DIR/inc ]; then
    set +o xtrace
    echo "missing devstack/inc"
    exit 1
fi

# ``stack.sh`` keeps project libraries here
# Make sure ``$TOP_DIR/lib`` directory is present
if [ ! -d $TOP_DIR/lib ]; then
    set +o xtrace
    echo "missing devstack/lib"
    exit 1
fi

# Check if run in POSIX shell
if [[ "${POSIXLY_CORRECT}" == "y" ]]; then
    set +o xtrace
    echo "You are running POSIX compatibility mode, DevStack requires bash 4.2 or newer."
    exit 1
fi

# OpenStack is designed to be run as a non-root user; Horizon will fail to run
# as **root** since Apache will not serve content from **root** user).
# ``stack.sh`` must not be run as **root**.  It aborts and suggests one course of
# action to create a suitable user account.

if [[ $EUID -eq 0 ]]; then
    set +o xtrace
    echo "DevStack should be run as a user with sudo permissions, "
    echo "not root."
    echo "A \"stack\" user configured correctly can be created with:"
    echo " $TOP_DIR/tools/create-stack-user.sh"
    exit 1
fi

# OpenStack is designed to run at a system level, with system level
# installation of python packages. It does not support running under a
# virtual env, and will fail in really odd ways if you do this. Make
# this explicit as it has come up on the mailing list.
if [[ -n "$VIRTUAL_ENV" ]]; then
    set +o xtrace
    echo "You appear to be running under a python virtualenv."
    echo "DevStack does not support this, as we may break the"
    echo "virtualenv you are currently in by modifying "
    echo "external system-level components the virtualenv relies on."
    echo "We recommend you use a separate virtual-machine if "
    echo "you are worried about DevStack taking over your system."
    exit 1
fi

# Provide a safety switch for devstack. If you do a lot of devstack,
# on a lot of different environments, you sometimes run it on the
# wrong box. This makes there be a way to prevent that.
if [[ -e $HOME/.no-devstack ]]; then
    set +o xtrace
    echo "You've marked this host as a no-devstack host, to save yourself from"
    echo "running devstack accidentally. If this is in error, please remove the"
    echo "~/.no-devstack file"
    exit 1
fi

# Initialize variables:
LAST_SPINNER_PID=""

# Import common functions
source $TOP_DIR/functions

# Import 'public' stack.sh functions
source $TOP_DIR/lib/stack

# Determine what system we are running on.  This provides ``os_VENDOR``,
# ``os_RELEASE``, ``os_PACKAGE``, ``os_CODENAME``
# and ``DISTRO``
GetDistro

# Phase: local
rm -f $TOP_DIR/.localrc.auto
extract_localrc_section $TOP_DIR/local.conf $TOP_DIR/localrc $TOP_DIR/.localrc.auto

if [[ ! -r $TOP_DIR/stackrc ]]; then
    die $LINENO "missing $TOP_DIR/stackrc - did you grab more than just stack.sh?"
fi
source $TOP_DIR/stackrc

# write /etc/devstack-version
write_devstack_version

# Warn users who aren't on an explicitly supported distro, but allow them to
# override check and attempt installation with ``FORCE=yes ./stack``
SUPPORTED_DISTROS="bullseye|focal|jammy|f35|opensuse-15.2|opensuse-tumbleweed|rhel8|rhel9"
if [[ ! ${DISTRO} =~ $SUPPORTED_DISTROS ]]; then
    echo "WARNING: this script has not been tested on $DISTRO"
    if [[ "$FORCE" != "yes" ]]; then
        die $LINENO "If you wish to run this script anyway run with FORCE=yes"
    fi
fi

# Make sure the proxy config is visible to sub-processes
export_proxy_variables

# Remove services which were negated in ``ENABLED_SERVICES``
# using the "-" prefix (e.g., "-rabbit") instead of
# calling disable_service().
disable_negated_services

# We're not as **root** so make sure ``sudo`` is available
is_package_installed sudo || is_package_installed sudo-ldap || install_package sudo

# UEC images ``/etc/sudoers`` does not have a ``#includedir``, add one
sudo grep -q "^#includedir.*/etc/sudoers.d" /etc/sudoers ||
    echo "#includedir /etc/sudoers.d" | sudo tee -a /etc/sudoers

# Conditionally setup detailed logging for sudo
if [[ -n "$LOG_SUDO" ]]; then
    TEMPFILE=`mktemp`
    echo "Defaults log_output" > $TEMPFILE
    chmod 0440 $TEMPFILE
    sudo chown root:root $TEMPFILE
    sudo mv $TEMPFILE /etc/sudoers.d/00_logging
fi

# Set up DevStack sudoers
TEMPFILE=`mktemp`
echo "$STACK_USER ALL=(root) NOPASSWD:ALL" >$TEMPFILE
echo "Defaults:$STACK_USER secure_path=/sbin:/usr/sbin:/usr/bin:/bin:/usr/local/sbin:/usr/local/bin" >> $TEMPFILE
echo "Defaults:$STACK_USER !requiretty" >> $TEMPFILE
chmod 0440 $TEMPFILE
sudo chown root:root $TEMPFILE
sudo mv $TEMPFILE /etc/sudoers.d/50_stack_sh

# For Debian/Ubuntu make apt attempt to retry network ops on it's own
if is_ubuntu; then
    echo 'APT::Acquire::Retries "20";' | sudo tee /etc/apt/apt.conf.d/80retry  >/dev/null
fi

# Some distros need to add repos beyond the defaults provided by the vendor
# to pick up required packages.

function _install_epel {
    # epel-release is in extras repo which is enabled by default
    install_package epel-release

    # RDO repos are not tested with epel and may have incompatibilities so
    # let's limit the packages fetched from epel to the ones not in RDO repos.
    sudo dnf config-manager --save --setopt=includepkgs=debootstrap,dpkg epel
}
