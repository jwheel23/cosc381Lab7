from unittest import mock

import pytest

from presidio_anonymizer.operators import Encrypt, AESCipher
from presidio_anonymizer.entities import InvalidParamError
from presidio_anonymizer.operators import OperatorType


@pytest.mark.parametrize(
    "key",
    [
        "a" * 16,         # 128 bits = 16 bytes
        "b" * 24,         # 192 bits = 24 bytes
        "c" * 32,         # 256 bits = 32 bytes
        b"a" * 16,        # 128 bits as bytes
        b"b" * 24,        # 192 bits as bytes
        b"c" * 32,        # 256 bits as bytes
    ],
)
def test_valid_keys(key):
    """
    Black-box test: verify Encrypt.validate succeeds for valid key lengths.
    """
    encrypt = Encrypt()
    # Should not raise an exception
    encrypt.validate(params={"key": key})
    
@mock.patch.object(AESCipher, "encrypt")
def test_given_anonymize_then_aes_encrypt_called_and_its_result_is_returned(
    mock_encrypt,
):
    expected_anonymized_text = "encrypted_text"
    mock_encrypt.return_value = expected_anonymized_text

    anonymized_text = Encrypt().operate(text="text", params={"key": "key"})

    assert anonymized_text == expected_anonymized_text


@mock.patch.object(AESCipher, "encrypt")
def test_given_anonymize_with_bytes_key_then_aes_encrypt_result_is_returned(
        mock_encrypt,
):
    expected_anonymized_text = "encrypted_text"
    mock_encrypt.return_value = expected_anonymized_text

    anonymized_text = Encrypt().operate(text="text",
                                        params={"key": b'1111111111111111'})

    assert anonymized_text == expected_anonymized_text


def test_given_verifying_an_valid_length_key_no_exceptions_raised():
    Encrypt().validate(params={"key": "128bitslengthkey"})


def test_given_verifying_an_valid_length_bytes_key_no_exceptions_raised():
    Encrypt().validate(params={"key": b'1111111111111111'})


def test_given_verifying_an_invalid_length_key_then_ipe_raised():
    with pytest.raises(
        InvalidParamError,
        match="Invalid input, key must be of length 128, 192 or 256 bits",
    ):
        Encrypt().validate(params={"key": "key"})

@mock.patch.object(AESCipher, "is_valid_key_size", return_value=False)
def test_given_verifying_an_invalid_length_bytes_key_then_ipe_raised(mock_is_valid):
    with pytest.raises(
        InvalidParamError,
        match="Invalid input, key must be of length 128, 192 or 256 bits",
    ):
        Encrypt().validate(params={"key": b'1111111111111111'})

def test_operator_name():
    encrypt = Encrypt()
    assert encrypt.operator_name() == "encrypt"

def test_operator_type():
    encrypt = Encrypt()
    assert encrypt.operator_type() == OperatorType.Anonymize