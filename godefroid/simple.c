// build via:
// clang -m32 -O0 -o simplec.elf simple.c
void mystery(int *p) {
  *p = (int)p & 0xFFFFFFF;
}

int main (int argc, const char *argv[]) {

  int test_out = 0;

  mystery(&test_out);

  return  test_out;
}
