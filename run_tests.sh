# clean
cd test/basic_app && sh clean.sh && cd ../../ \
# pull compiler container
docker pull murachue/toolchain64:o32 && \
# compile the app
docker run -t  -w /basic_app -v $(pwd)/test/basic_app:/basic_app murachue/toolchain64:o32 sh -c "cd /basic_app && sh build.sh" && \
# split and compare
python3 test.py
