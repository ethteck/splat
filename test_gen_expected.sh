docker run --rm -it -v $(pwd):/splat -w /splat/test/basic_app splat-build make -C test/basic_app all && \
rm -rf $(pwd)/test/basic_app/expected && \
cp -r $(pwd)/test/basic_app/split $(pwd)/test/basic_app/expected
