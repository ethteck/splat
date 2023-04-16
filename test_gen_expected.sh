docker pull murachue/toolchain64:o32 && \
docker run -t --rm -w /basic_app -v $(pwd)/test/basic_app:/basic_app murachue/toolchain64:o32 sh -c "cd /basic_app && sh build.sh" && \
rm -rf $(pwd)/test/basic_app/expected && \
cp -r $(pwd)/test/basic_app/split $(pwd)/test/basic_app/expected
