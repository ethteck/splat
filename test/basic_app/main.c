volatile int test = 0;

void _start()
{
    for (;;)
    {
        test++;
    }
}
