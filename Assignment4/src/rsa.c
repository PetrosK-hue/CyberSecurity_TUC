#include "rsa.h"
#include "utils.h"

/*
 * Sieve of Eratosthenes Algorithm
 * https://en.wikipedia.org/wiki/Sieve_of_Eratosthenes
 *
 * arg0: A limit
 * arg1: The size of the generated primes list. Empty argument used as ret val
 *
 * ret:  The prime numbers that are less or equal to the limit
 */
size_t *sieve_of_eratosthenes(int limit, int *primes_sz)
{
  size_t *primes;

  /* TODO */
  size_t *array;
  array = calloc(limit, sizeof(size_t));
  int k = 0;

  for (int i = 2; i < (int)sqrt(limit); i++)
  {
    if (!array[i])
    {
      for (int j = i * i; j < limit; j = j + i)
      {
        array[j] = 1;
      }
    }
  }

  for (int i = 0; i < 255; i++)
  {

    if (array[i] == 0 && i != 0 && i != 1)
    {
      k = k + 1;
    }
  }

  primes = calloc(k, sizeof(size_t));

  k = 0;

  for (int i = 0; i < 255; i++)
  {

    if (array[i] == 0 && i != 0 && i != 1)
    {
      primes[k] = i;
      k = k + 1;
    }
  }

  *primes_sz = k;

  if (primes_sz == NULL)
  {
    return (size_t *)primes_sz;
  }
  else
  {
    return primes;
  }
}

/*
 * Greatest Common Denominator
 *
 * arg0: first number
 * arg1: second number
 *
 * ret: the GCD
 */
int gcd(int a, int b)
{

  /* TODO */

  int i, GCD;

  for (i = 1; i <= a && i <= b; i++)
  {
    if (a % i == 0 && b % i == 0)
    {
      GCD = i;
    }
  }

  return GCD;
}

/*
 * Chooses 'e' where
 *     1 < e < fi(n) AND gcd(e, fi(n)) == 1
 *
 * arg0: fi(n)
 *
 * ret: 'e'
 */
size_t choose_e(size_t fi_n, size_t *primes_pool)
{
  size_t e;

  /* TODO */

  int random_index_e = rand() % 54;
  e = primes_pool[random_index_e];

  while (e % fi_n == 0 || gcd(e, fi_n) != 1)
  {
    int random_index_e = rand() % 54;
    e = primes_pool[random_index_e];
  }

  return e;
}

/*
 * Calculates the modular inverse
 *
 * arg0: first number
 * arg1: second number
 *
 * ret: modular inverse
 */
size_t mod_inverse(size_t a, size_t b)
{
  /* TODO */
  size_t d;
  a = a % b;

  for (int d = 1; d < b; d++)
  {
    if ((a * d) % b == 1)
    {
      return (size_t)d;
    }
  }
}

/*
 * Generates an RSA key pair and saves
 * each key in a different file
 */
void rsa_keygen(void)
{
  size_t p;
  size_t q;
  size_t n;
  size_t fi_n;
  size_t e;
  size_t d;

  /* TODO */
  size_t *primes_pool;
  int primes_sz;
  primes_pool = sieve_of_eratosthenes(RSA_SIEVE_LIMIT, &primes_sz);

  srand(time(NULL));

  int random_index_p = rand() % primes_sz;
  p = primes_pool[random_index_p];

  int random_index_q = rand() % primes_sz;
  q = primes_pool[random_index_q];
  n = p * q;
  fi_n = (p - 1) * (q - 1);
  e = choose_e(fi_n, primes_pool);
  d = mod_inverse(e, fi_n);

  write_to_file("public.key", n, d);
  write_to_file("private.key", n, e);
}

/*
 * Encrypts an input file and dumps the ciphertext into an output file
 *
 * arg0: path to input file
 * arg1: path to output file
 * arg2: path to key file
 */
void rsa_encrypt(char *input_file, char *output_file, char *key_file)
{

  /* TODO */

  unsigned char *file_buffer;
  unsigned char *key;
  unsigned char *ciphertext;

  size_t temp;

  int file_length = 0;

  file_buffer = read_file(input_file);
  file_length = get_file_length(input_file);

  key = read_file(key_file);

  file_length = file_length;

  int ciphertext_len = file_length * (sizeof(size_t));

  ciphertext = malloc(ciphertext_len);

  memset(ciphertext, 0x00, ciphertext_len);

  size_t first_8_bytes_of_key, second_8_bytes_of_key;

  memcpy(&first_8_bytes_of_key, key, 8);

  memcpy(&second_8_bytes_of_key, key + 8, 8);

  for (int i = 0; i < file_length; i++)
  {
    temp = mod_expo((size_t)file_buffer[i], second_8_bytes_of_key, first_8_bytes_of_key);

    memcpy(ciphertext + i * 8, &temp, 8);
  }

  write_cipher_to_file(output_file, ciphertext, ciphertext_len);
}

/*
 * Decrypts an input file and dumps the plaintext into an output file
 *
 * arg0: path to input file
 * arg1: path to output file
 * arg2: path to key file
 */
void rsa_decrypt(char *input_file, char *output_file, char *key_file)
{

  /* TODO */
  unsigned char *file_buffer;
  unsigned char *key;
  unsigned char *decryptedtext;

  size_t temp;

  int file_length = 0;

  file_buffer = read_file(input_file);
  file_length = get_file_length(input_file);

  key = read_file(key_file);

  int decryptedtext_len = file_length / (sizeof(size_t));

  decryptedtext = malloc(decryptedtext_len);

  size_t first_8_bytes_of_key, second_8_bytes_of_key;

  memcpy(&first_8_bytes_of_key, key, 8);

  memcpy(&second_8_bytes_of_key, key + 8, 8);

  int j = 0;

  for (int i = 0; i < file_length; i++)
  {
    if (i % 8 == 0)
    {
      memcpy(&temp, file_buffer + j * 8, 8);

      decryptedtext[j] = mod_expo(temp, second_8_bytes_of_key, first_8_bytes_of_key);

      j = j + 1;
    }
  }

  write_plaintext_to_file(output_file, decryptedtext, decryptedtext_len);
}
// Mod exponentiation
size_t mod_expo(size_t base, size_t exp, size_t mod)
{

  size_t result;
  base = base % mod;

  if (mod == 1)
    return 0;

  assert((mod - 1) * (mod - 1));
  result = 1;
  base = base % mod;
  while (exp > 0)
  {
    if (exp % 2 == 1)
    {
      result = (result * base) % mod;
    }
    exp = exp >> 1;
    base = (base * base) % mod;
  }
  return result;
}
