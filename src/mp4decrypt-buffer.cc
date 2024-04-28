#include <map>
#include <napi.h>
#include "Ap4CommonEncryption.h"

void CleanUp(Napi::Env env, char* data, AP4_MemoryByteStream* stream) {
    stream->Release();
}

class DecryptWorker : public Napi::AsyncWorker {
private:
    AP4_MemoryByteStream* input;
    AP4_MemoryByteStream* output;
    AP4_ProtectionKeyMap key_map;

public:
    DecryptWorker(Napi::Function& callback, AP4_MemoryByteStream* input, const std::map<std::string, std::string>& keys)
        : Napi::AsyncWorker(callback), input(input) {
        for (const auto& [hex_kid, hex_key] : keys) {
            unsigned char kid[16], key[16];
            AP4_ParseHex(hex_kid.c_str(), kid, 16);
            AP4_ParseHex(hex_key.c_str(), key, 16);
            key_map.SetKeyForKid(kid, key, 16);
        }
    }

    ~DecryptWorker() {}

    void Execute() override {
        input->Seek(0);
        output = new AP4_MemoryByteStream();
        AP4_Processor* processor = new AP4_CencDecryptingProcessor(&key_map);
        processor->Process(*input, *output, NULL);
        delete processor;
        input->Release();
    }

    void OnOK() override {
        char* resultData = const_cast<char*>(reinterpret_cast<const char*>(output->GetData()));
        Napi::Buffer<char> outBuffer = Napi::Buffer<char>::New(
            Env(),
            resultData,
            output->GetDataSize(),
            CleanUp,
            output
        );
        Callback().Call({outBuffer});
    }
};

Napi::Value Decrypt(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() < 3 || !info[0].IsBuffer() || !info[1].IsObject() || !info[2].IsFunction()) {
        Napi::TypeError::New(env, "Invalid arguments").ThrowAsJavaScriptException();
        return env.Undefined();
    }

    Napi::Buffer<char> buffer = info[0].As<Napi::Buffer<char>>();
    Napi::Object keysObject = info[1].As<Napi::Object>();
    Napi::Function callback = info[2].As<Napi::Function>();

    std::map<std::string, std::string> keys;

    keysObject.ForEach([&](const Napi::Value& key, const Napi::Value& value) {
        keys[key.ToString().Utf8Value()] = value.ToString().Utf8Value();
    });

    AP4_UI08* inputData = reinterpret_cast
    <AP4_UI08*>(buffer.Data());
    AP4_MemoryByteStream* input = new AP4_MemoryByteStream(inputData, buffer.ByteLength());

    DecryptWorker* worker = new DecryptWorker(callback, input, keys);
    worker->Queue();

    return env.Undefined();
}

Napi::Object Init(Napi::Env env, Napi::Object exports) {
    exports.Set(Napi::String::New(env, "decrypt"), Napi::Function::New(env, Decrypt));
    return exports;
}

NODE_API_MODULE(NODE_GYP_MODULE_NAME, Init)
