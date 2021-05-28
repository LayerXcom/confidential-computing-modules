#include <stdbool.h>

#define ADDRESS_SIZE 20

#define DB_VALUE_SIZE (STATE_SIZE + RANDOMNESS_SIZE)

#define PUBKEY_SIZE 32

#define RANDOMNESS_SIZE 32

#define SIG_SIZE 64

#define STATE_SIZE 8

typedef enum {
  /**
   * Ok = Success = 1.
   */
  Ok = 1,
  /**
   * Failure = Error = 0.
   */
  Failure = 0,
} ResultStatus;

/**
 * Status for Ecall
 */
typedef struct {
  uint32_t _0;
} EnclaveStatus;

/**
 * Status for Ocall
 */
typedef struct {
  uint32_t _0;
} UntrustedStatus;

/**
 * Returned from getting state operations.
 */
typedef struct {
  const uint8_t *_0;
} EnclaveState;

/**
 * A wrapper to a raw mutable/immutable pointer.
 * The Edger8r will copy the data to the protected stack when you pass a pointer through the EDL.
 */
typedef struct {
  const uint8_t *ptr;
  bool _mut;
} RawPointer;

typedef uint8_t RawSig[SIG_SIZE];

typedef uint8_t RawPubkey[PUBKEY_SIZE];

typedef uint8_t RawChallenge[RANDOMNESS_SIZE];
