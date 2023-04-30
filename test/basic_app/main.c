volatile int test = 1;

// bin
const char bin_data[] = {0,1,2,3,4,5,6,7};

volatile int switch_arg = 0;

int do_switch()
{
    switch(switch_arg)
    {
        case 0:
        return 7;
        case 1:
        return 6;
        case 2:
        return 5;
        case 3:
        return 4;
        case 4:
        return 3;
        case 5:
        return 2;
        case 6:
        return 1;
        case 7:
        return 0; 
    }
    return 0;
}

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
    do_switch();
    mymb();
    for (;;)
    {
        test++;
    }
}
