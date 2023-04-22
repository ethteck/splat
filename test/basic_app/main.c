volatile int test = 1;

// bin
const char bin_data[] = {0,1,2,3,4,5,6,7};

// hasm
// borrowed from http://www.discoversdk.com/knowledge-base/mips-assembly-examples-with-gcc
void mymb()
{
    asm volatile(
            ".set push\n\t"
            ".set noreorder\n\t"
            ".set mips2\n\t"
            "sync\n\t"
            ".set pop"
            :::"memory");
}

// c
void _start()
{
    mymb();
    for (;;)
    {
        test++;
    }
}
