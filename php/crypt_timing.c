#include <stdio.h>
#include <sys/time.h>

double microtime() {
  static struct timeval x;
  gettimeofday(&x, NULL);
  return (double) x.tv_sec + ((double) x.tv_usec / 1000000.0);
}

void doit() {
  double t0,t1;

  const int imax = 1000;
  const char* key = "mypassword";
  const char* salt_bf = "$2a$99$01234567890ABCDEF$";
  const char* salt_256 = "$5$rounds=5000$01234567890ABCDEF$";
  const char* salt_512 = "$6$rounds=5000$01234567890ABCDEF$";

  t0 = microtime();
  for (int i = 0; i < imax; ++i) {
    crypt(key, salt_512);
  }
  t1 = microtime();
  printf("sha_512\t%f RPS\n", (double)(imax)/(t1-t0)  );


  t0 = microtime();
  for (int i = 0; i < imax; ++i) {
    crypt(key, salt_256);
  }
  t1 = microtime();
  printf("sha_256\t%f RPS\n", (double)(imax)/(t1-t0)  );
}

int main() {
  doit();
}
