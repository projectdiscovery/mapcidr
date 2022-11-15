#!/bin/bash

echo "::group::Build mapcidr"
cd ../cmd/mapcidr
go build
mv mapcidr ../../integration_tests/mapcidr
echo "::endgroup::"
echo "::group::Build mapcidr integration-test"
cd ../integration-test
go build
cp -rf goldenfiles ../../integration_tests/
mv integration-test ../../integration_tests/integration-test
cd ../../integration_tests
echo "::endgroup::"
echo "::group::Running mapcidr integration-test"
./integration-test
if [ $? -eq 0 ]
then
  echo "Integration test passed"
else
  rm integration-test mapcidr 2>/dev/null
  exit 1
fi
echo "::group::Running mapcidr integration-test as library"
export RUN_AS=library
./integration-test
if [ $? -eq 0 ]
then
  echo "Integration test passed"
  rm integration-test mapcidr 2>/dev/null
  exit 0
else
  rm integration-test mapcidr 2>/dev/null
  exit 1
fi
