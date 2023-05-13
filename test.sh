#!/bin/bash

function is_equal_to {
  [[ $1 == "true" || $2 == "true" ]]
}

a=False
b=True
if is_equal_to $a $b; then
  echo "test_is_equal_to passed"
else
  echo "test_is_equal_to failed"
fi
