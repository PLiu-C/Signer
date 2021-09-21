{
  'targets': [
    {
      'target_name': 'signer',
      'sources': [ '../impl/napi.cpp', '../impl/smcrypto.cpp' ],
      'cflags!': [ '-fno-exceptions' ],
      'cflags_cc!': [ '-fno-exceptions' ],
      'xcode_settings': {
        'GCC_ENABLE_CPP_EXCEPTIONS': 'YES',
        'CLANG_CXX_LIBRARY': 'libc++',
        'MACOSX_DEPLOYMENT_TARGET': '10.15',
      },
      'cflags_cc': [ '-std=c++14', '-DNDEBUG=1' ],
      'variables': { 'botan_root%': '/Users/pliu/neo/github/botan' },
      'libraries': [ '<(botan_root)/lib/libbotan-2.a' ],
      'include_dirs': [ "<(botan_root)/include/botan-2", "<!@(node -p \"require('node-addon-api').include\")" ],
      'defines': [ 'NAPI_CPP_EXCEPTIONS' ],
      'dependencies': ["<!(node -p \"require('node-addon-api').gyp\")"]
    }
  ]
}
