export default async function () {
    console.log(await pbkdf2Decrypt("vucmai0dDDT5X8TFMQ2TnXJYxzS5lxLBp8bH88fENehHcyRxK26gi2qMAK74dMQq",
        "Xejc98gptDn7Dov12RcZZN+29M7NxWwTdMAfvldXXHA98PH3NJOBjLDFZIm8tJLZKxIZgtFzmfbtnJLx12Ij1SWaKpP0Lz2tx/Ga7CrlFTdKOX64qoJuVvSh9rQioFU1+OhXGV3ZSw2tI06fHxOPGw8n2/5k4EznmxEulNN/waldqLcUGXOJmwBFUqK6zoGB",
        1000,
        "NIA+hzM5wkE="))

}


function base64ToArrayBuffer(base64String: string): ArrayBufferLike {
    const binaryString = atob(base64String);
    const length = binaryString.length;
    const bytes = new Uint8Array(length);
    binaryString.split('').forEach((char, index) => {
        bytes[index] = char.charCodeAt(0);
    });
    return bytes.buffer;
}
async function pbkdf2Decrypt(secret: string, encryptedString: string, iterations: number, salt: string): Promise<string>{
    const ivlen = 16;
    const keylen = 32;
    const bitsLength = (ivlen + keylen) * 8;

    const encodedPassword = new TextEncoder().encode(secret);
    const encodedSalt = base64ToArrayBuffer(salt);
    const importedKey = await crypto.subtle.importKey('raw', encodedPassword, 'PBKDF2', false, ['deriveBits']);
    const params = { name: 'PBKDF2', hash: 'SHA-256', salt: encodedSalt, iterations: iterations };
    const derivation = await crypto.subtle.deriveBits(params, importedKey, bitsLength);

    const derivedKey = derivation.slice(0, keylen);
    const iv = derivation.slice(keylen);
    const cookieBuffer = base64ToArrayBuffer(encryptedString);
    const importedDecryptionKey = await crypto.subtle.importKey('raw', derivedKey, { name: 'AES-CBC' }, false, [
        'decrypt',
    ]);
    const decrypted = await crypto.subtle.decrypt(
        {
            name: 'AES-CBC',
            iv: iv,
        },
        importedDecryptionKey,
        cookieBuffer,
    );
    return new TextDecoder('utf-8').decode(decrypted);
}
