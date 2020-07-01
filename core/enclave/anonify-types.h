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
 * Bridged type from enclave to host to send a JoinGroup transaction.
 */
typedef struct {
  /**
   * A pointer to the output of the report using `ocall_save_to_memory()`.
   */
  const uint8_t *report;
  const uint8_t *report_sig;
  const uint8_t *handshake;
} RawJoinGroupTx;

/**
 * Bridged type from enclave to host to modify state transaction.
 */
typedef struct {
  uint64_t state_id;
  const uint8_t *ciphertext;
  const uint8_t *enclave_sig;
  const uint8_t *msg;
} RawInstructionTx;

/**
 * Bridged type from enclave to host to send a handshake transaction.
 */
typedef struct {
  const uint8_t *handshake;
} RawHandshakeTx;

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

typedef uint8_t Address[ADDRESS_SIZE];

/**
 * Key Value data stored in an Enclave
 */
typedef struct {
  Address address;
  uint32_t mem_id;
  const uint8_t *state;
} RawUpdatedState;

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
