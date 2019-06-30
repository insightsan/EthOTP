import crypto from 'crypto';
import EthCrypto from 'eth-crypto';

export default class EthOTP {

  constructor() {
    this.generatedChallenges = {};
    this.expirySeconds = 30;
  }

  /**
   * Generate a random challenge string to use as a challenge to be signed
   * @return {string} challenge string
   */
  generateChallenge = () => {
    const challenge = crypto.randomBytes(32).toString('hex');

    const d = new Date();
    this.generatedChallenges[challenge] = d.setSeconds(d.getSeconds() + this.expirySeconds);

    return challenge;
  };

  /**
   * Performs challenge payload validation and verification.
   * @param challengePayload
   * @return {boolean} if challenge response payload is valid and verified
   */
  validateAndVerifyChallengePayload = (challengePayload) => {
    if (!this._isVerifiedPayload(challengePayload)) {
      return false;
    } else if (!this._validateChallenge(challengePayload.message)) {
      return false;
    }
    return true;
  };

  /**
   * Checks with the list of generated challenges if a challenge is valid/not-expired
   * @param challenge to check
   * @return {boolean} result of check
   */
  _isValidChallenge = (challenge) => {
    // TODO check expiry time here?
    return this.generatedChallenges[challenge] !== undefined;
  };


  /**
   * Removes a challenge from the list of generated challenges
   * @param challenge
   */
  _removeValidatedChallenge = (challenge) => {
    delete this.generatedChallenges[challenge];
  };

  /**
   *
   * @param challenge
   * @return {boolean}
   */
  _validateChallenge = (challenge) => {
    const result = this._isValidChallenge(challenge);
    if (result) {
      this._removeValidatedChallenge(challenge);
      return true
    }
    return false;
  };


  /**
   * Verifies that a payload has a valid message that corresponds to being signed by the payload's address by a
   * @param payload
   * @return {boolean}
   */
  _isVerifiedPayload = (payload) => {
    if (payload === undefined) {
      return false;
    }

    // TODO require encryption eventually? is that extra layer even useful at that point though...?
    return this._isVerified(payload.message, payload.signature, payload.address);
  };

  _isVerified = (message, signature, address) => {
    if (message === undefined || address === undefined || signature === undefined ||
      message.length === 0 || address.length === 0 || signature.length === 0) {
      return false;
    }

    const derivedAddress = EthCrypto.recover(
      signature,
      EthCrypto.hash.keccak256(message)
    );

    return address !== undefined && derivedAddress === address;

  };
}


