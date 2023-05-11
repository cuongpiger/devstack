#!/bin/bash

DEVSTACK_VERSION_NAME=${DEVSTACK_VERSION_NAME:-zed}
CONDA_ENABLED=${CONDA_ENABLED:-True}
CONDA_PYTHON_VERSION=${CONDA_PYTHON_VERSION:-3.8}

KEYSTONE_DIRECTORY_PATH=${KEYSTONE_DIRECTORY_PATH:-/opt/stack/keystone}
KEYSTONE_CONDA_ENV=${KEYSTONE_CONDA_ENV:-keystone_$DEVSTACK_VERSION_NAME}
KEYSTONE_PYTHON_CMD=""

OSPROFILER_DIRECTORY_PATH=${OSPROFILER_DIRECTORY_PATH:-/opt/stack/osprofiler}

function check_conda_is_installed {
  if command -v conda >/dev/null 2>&1; then
    return 0 # Conda is installed
  else
    return 1 # Conda is not installed
  fi
}

function check_conda_env_exists {
  local env_name=$1
  if conda info --envs | grep -q "^${env_name}\s"; then
    return 0 # Conda environment exists
  else
    return 1 # Conda environment does not exist
  fi
}

function update_service_python_command {
  local py_cmd=$1
  local env=$2

  if [[ "$py_cmd" == *"$2"* ]]; then
    KEYSTONE_PYTHON_CMD="$py_cmd"
    echo "Python executable found at '$KEYSTONE_PYTHON_CMD'."
  else
    echo "The string '$py_cmd' is not match anything."
  fi
}

function get_conda_python_path {
  local env_name=$1
  local conda_root=$(conda info --base)
  local python_path="${conda_root}/envs/${env_name}/bin/python"

  if [ -x "$python_path" ]; then
    update_service_python_command "$python_path" "$KEYSTONE_CONDA_ENV"
  else
    echo "Python executable not found for the '$env_name' environment."
    exit 1
  fi
}

function create_conda_env_for {
  local env_name=$1
  if check_conda_is_installed && check_conda_env_exists "$env_name"; then
    echo "The environment '$env_name' exists."
  else
    echo "The environment '$env_name' does not exist or Conda is not installed."
    conda create -n $env_name python=$CONDA_PYTHON_VERSION pip
  fi

  get_conda_python_path "$env_name"
}

if [[ "$CONDA_ENABLED" == "True" ]]; then
  echo "hah"
fi