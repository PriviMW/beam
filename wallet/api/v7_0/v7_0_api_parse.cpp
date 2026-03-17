// Copyright 2018 The Beam Team
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
#include "v7_0_api.h"
#include "version.h"

namespace beam::wallet
{
    namespace
    {
        uint32_t parseTimeout(V70Api& api, const nlohmann::json& params)
        {
            if(auto otimeout = api.getOptionalParam<uint32_t>(params, "timeout"))
            {
                return *otimeout;
            }
            return 0;
        }

        bool ExtractPoint(ECC::Point::Native& point, const json& j)
        {
            auto s = type_get<NonEmptyString>(j);
            auto buf = from_hex(s);
            ECC::Point pt;
            Deserializer dr;
            dr.reset(buf);
            dr& pt;

            return point.ImportNnz(pt);
        }
    }

    template<>
    const char* type_name<ECC::Point::Native>()
    {
        return "hex encoded elliptic curve point";
    }

    template<>
    bool type_check<ECC::Point::Native>(const json& j)
    {
        ECC::Point::Native pt;
        return type_check<NonEmptyString>(j) && ExtractPoint(pt, j);
    }

    template<>
    ECC::Point::Native type_get<ECC::Point::Native>(const json& j)
    {
        ECC::Point::Native pt;
        ExtractPoint(pt, j);
        return pt;
    }

    std::pair<IPFSAdd, IWalletApi::MethodInfo> V70Api::onParseIPFSAdd(const JsonRpcId& id, const nlohmann::json& params)
    {
        IPFSAdd message;
        message.timeout = parseTimeout(*this, params);

        // Support both JSON array [0,123,255,...] and base64 string for "data" param.
        // Base64 is more memory-efficient for large files on mobile.
        if (params.contains("data"))
        {
            const auto& dataParam = params["data"];
            if (dataParam.is_array())
            {
                dataParam.get<std::vector<uint8_t>>().swap(message.data);
            }
            else if (dataParam.is_string())
            {
                // Decode base64 string
                auto b64str = dataParam.get<std::string>();
                {
                    static const std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
                    auto& out = message.data;
                    out.reserve(b64str.size() * 3 / 4);
                    int val = 0, bits = -8;
                    for (unsigned char c : b64str) {
                        if (c == '=') break;
                        auto pos = chars.find(c);
                        if (pos == std::string::npos) continue;
                        val = (val << 6) + static_cast<int>(pos);
                        bits += 6;
                        if (bits >= 0) { out.push_back(static_cast<uint8_t>((val >> bits) & 0xFF)); bits -= 8; }
                    }
                }
            }
            else
            {
                throw jsonrpc_exception(ApiError::InvalidParamsJsonRpc, "Parameter 'data' must be an array or base64 string.");
            }

            if (message.data.empty())
            {
                throw jsonrpc_exception(ApiError::InvalidParamsJsonRpc, "Parameter 'data' must not be empty.");
            }
        }
        else
        {
            throw jsonrpc_exception(ApiError::InvalidParamsJsonRpc, "Missing mandatory parameter 'data'.");
        }

        if (auto opin = getOptionalParam<bool>(params, "pin"))
        {
            message.pin = *opin;
        }

        return std::make_pair(std::move(message), MethodInfo());
    }

    void V70Api::getResponse(const JsonRpcId& id, const IPFSAdd::Response& res, json& msg)
    {
        msg = json
        {
            {JsonRpcHeader, JsonRpcVersion},
            {"id", id},
            {"result",
                {
                    {"hash", res.hash},
                    {"pinned", res.pinned}
                }
            }
        };
    }

    std::pair<IPFSHash, IWalletApi::MethodInfo> V70Api::onParseIPFSHash(const JsonRpcId& id, const nlohmann::json& params)
    {
        IPFSHash message;
        message.timeout = parseTimeout(*this, params);

        json data = getMandatoryParam<NonEmptyJsonArray>(params, "data");
        data.get<std::vector<uint8_t>>().swap(message.data);

        return std::make_pair(std::move(message), MethodInfo());
    }

    void V70Api::getResponse(const JsonRpcId& id, const IPFSHash::Response& res, json& msg)
    {
        msg = json
            {
                {JsonRpcHeader, JsonRpcVersion},
                {"id", id},
                {"result",
                    {
                        {"hash", res.hash}
                    }
                }
            };
    }

    std::pair<IPFSGet, IWalletApi::MethodInfo> V70Api::onParseIPFSGet(const JsonRpcId& id, const nlohmann::json& params)
    {
        IPFSGet message;
        message.timeout = parseTimeout(*this, params);
        message.hash = getMandatoryParam<NonEmptyString>(params, "hash");
        if (auto ob64 = getOptionalParam<bool>(params, "base64"))
        {
            message.base64 = *ob64;
        }
        return std::make_pair(std::move(message), MethodInfo());
    }

    void V70Api::getResponse(const JsonRpcId& id, const IPFSGet::Response& res, json& msg)
    {
        json result = {{"hash", res.hash}};
        if (res.base64)
        {
            // Encode data to base64 string
            static const char chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            std::string b64;
            b64.reserve((res.data.size() + 2) / 3 * 4);
            int val = 0, bits = -6;
            for (uint8_t c : res.data) {
                val = (val << 8) + c;
                bits += 8;
                while (bits >= 0) { b64.push_back(chars[(val >> bits) & 0x3F]); bits -= 6; }
            }
            if (bits > -6) b64.push_back(chars[(val << (0 - bits)) & 0x3F]);
            while (b64.size() % 4) b64.push_back('=');
            result["data"] = b64;
        }
        else
        {
            result["data"] = res.data;
        }
        msg = json
        {
            {JsonRpcHeader, JsonRpcVersion},
            {"id", id},
            {"result", result}
        };
    }

    std::pair<IPFSPin, IWalletApi::MethodInfo> V70Api::onParseIPFSPin(const JsonRpcId& id, const nlohmann::json& params)
    {
        IPFSPin message;
        message.timeout = parseTimeout(*this, params);
        message.hash = getMandatoryParam<NonEmptyString>(params, "hash");
        return std::make_pair(std::move(message), MethodInfo());
    }

    void V70Api::getResponse(const JsonRpcId& id, const IPFSPin::Response& res, json& msg)
    {
        msg = json
            {
                {JsonRpcHeader, JsonRpcVersion},
                {"id", id},
                {"result",
                    {
                        {"hash", res.hash}
                    }
                }
            };
    }

    std::pair<IPFSUnpin, IWalletApi::MethodInfo> V70Api::onParseIPFSUnpin(const JsonRpcId& id, const nlohmann::json& params)
    {
        IPFSUnpin message;
        message.hash = getMandatoryParam<NonEmptyString>(params, "hash");
        return std::make_pair(std::move(message), MethodInfo());
    }

    void V70Api::getResponse(const JsonRpcId& id, const IPFSUnpin::Response& res, json& msg)
    {
        msg = json
        {
            {JsonRpcHeader, JsonRpcVersion},
            {"id", id},
            {"result",
                {
                    {"hash", res.hash}
                }
            }
        };
    }

    std::pair<IPFSGc, IWalletApi::MethodInfo> V70Api::onParseIPFSGc(const JsonRpcId& id, const nlohmann::json& params)
    {
        IPFSGc message;
        message.timeout = parseTimeout(*this, params);
        return std::make_pair(message, MethodInfo());
    }

    void V70Api::getResponse(const JsonRpcId& id, const IPFSGc::Response& res, json& msg)
    {
        msg = json
        {
            {JsonRpcHeader, JsonRpcVersion},
            {"id", id},
            {"result",
                {
                    {"result", true}
                }
            }
        };
    }

    std::pair<SignMessage, IWalletApi::MethodInfo> V70Api::onParseSignMessage(const JsonRpcId& id, const nlohmann::json& params)
    {
        SignMessage message;
        message.message = getMandatoryParam<NonEmptyString>(params, "message");
        auto km = getMandatoryParam<NonEmptyString>(params, "key_material");
        message.keyMaterial = from_hex(km);
        return std::make_pair(message, MethodInfo());
    }

    void V70Api::getResponse(const JsonRpcId& id, const SignMessage::Response& res, json& msg)
    {
        msg = json
        {
            {JsonRpcHeader, JsonRpcVersion},
            {"id", id},
            {"result",
                {
                    {"signature", res.signature}
                }
            }
        };
    }

    std::pair<VerifySignature, IWalletApi::MethodInfo> V70Api::onParseVerifySignature(const JsonRpcId& id, const nlohmann::json& params)
    {
        VerifySignature message;
        message.message = getMandatoryParam<NonEmptyString>(params, "message");
        message.publicKey = getMandatoryParam<ECC::Point::Native>(params, "public_key");
        message.signature = getMandatoryParam<ValidHexBuffer>(params, "signature");
        
        return std::make_pair(message, MethodInfo());
    }

    void V70Api::getResponse(const JsonRpcId& id, const VerifySignature::Response& res, json& msg)
    {
        msg = json
        {
            {JsonRpcHeader, JsonRpcVersion},
            {"id", id},
            {"result", res.result }
        };
    }
}
