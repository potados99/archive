import 'dart:math';

class ZipCrypto {
  static const int KEY0 = 0x12345678;
  static const int KEY1 = 0x23456789;
  static const int KEY2 = 0x34567890;

  int key0 = KEY0;
  int key1 = KEY1;
  int key2 = KEY2;

  final List<int> crcTable = List.generate(256, (i) {
    int r = i;
    for (int j = 0; j < 8; j++) {
      if ((r & 1) != 0) {
        r = (r >> 1) ^ 0xEDB88320;
      } else {
        r >>= 1;
      }
    }
    return r;
  });

  ZipCrypto(String password) {
    for (int i = 0; i < password.length; i++) {
      _updateKeys(password.codeUnitAt(i));
    }
  }

  void _updateKeys(int charValue) {
    key0 = _crc32(key0, charValue);
    key1 = ((key1 + (key0 & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF;
    key2 = _crc32(key2, key1 >> 24);
  }

  int _crc32(int oldCrc, int byteValue) {
    return (oldCrc >> 8) ^ crcTable[(oldCrc ^ byteValue) & 0xFF];
  }

  int _decryptByte() {
    int temp = ((key2 & 0xFFFF) | 2);
    return ((temp * (temp ^ 1)) >> 8) & 0xFF;
  }

  List<int> encrypt(List<int> data, int crc32) {
    final result = <int>[];

    // Create and encrypt 12-byte header
    final rand = Random.secure();
    final header = List<int>.generate(11, (_) => rand.nextInt(256));
    header.add((crc32 >> 24) & 0xFF);

    for (final b in header) {
      result.add(b ^ _decryptByte());
      _updateKeys(b);
    }

    // Encrypt file data
    for (final b in data) {
      final encrypted = b ^ _decryptByte();
      _updateKeys(b);
      result.add(encrypted);
    }

    return result;
  }
}