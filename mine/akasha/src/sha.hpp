#ifndef SHA384_HPP
#define SHA384_HPP

#include <array>
#include <bit>
#include <concepts>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace crypto {

class SHA384 {
public:
    static constexpr size_t HASH_SIZE = 48;
    static constexpr size_t BLOCK_SIZE = 128;
    
    using hash_type = std::array<std::uint8_t, HASH_SIZE>;
    using state_type = std::array<std::uint64_t, 8>;
    
private:
    static constexpr std::array<std::uint64_t, 80> K = {
        0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
        0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
        0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
        0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
        0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
        0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
        0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
        0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
        0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
        0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
        0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
        0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
        0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
        0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
        0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
        0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
        0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
        0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
        0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
        0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
    };
    
    static constexpr state_type INITIAL_STATE = {
        0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939,
        0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4
    };
    
    static constexpr std::array<std::uint64_t, 6> XOR_CONSTANTS = {
        0x5aa5a55aa5a55aa5, 0x3cc3c33cc3c33cc3, 0x0ff0f00ff0f00ff0,
        0x5555aaaa5555aaaa, 0x3333cccc3333cccc, 0x0f0f0f0f0f0f0f0f
    };
    
    state_type state_;
    std::array<std::uint8_t, BLOCK_SIZE> buffer_;
    std::uint64_t buffer_len_;
    std::uint64_t total_len_;
    
    // Optimized rotate right
    [[nodiscard]] static constexpr std::uint64_t rotr(std::uint64_t x, unsigned n) noexcept {
        return std::rotr(x, n);
    }
    
    // SHA-512 family functions (optimized)
    [[nodiscard]] static constexpr std::uint64_t Ch(std::uint64_t x, std::uint64_t y, std::uint64_t z) noexcept {
        return (x & y) ^ (~x & z);
    }
    
    [[nodiscard]] static constexpr std::uint64_t Maj(std::uint64_t x, std::uint64_t y, std::uint64_t z) noexcept {
        return (x & y) ^ (x & z) ^ (y & z);
    }
    
    [[nodiscard]] static constexpr std::uint64_t Sigma0(std::uint64_t x) noexcept {
        return rotr(x, 28) ^ rotr(x, 34) ^ rotr(x, 39);
    }
    
    [[nodiscard]] static constexpr std::uint64_t Sigma1(std::uint64_t x) noexcept {
        return rotr(x, 14) ^ rotr(x, 18) ^ rotr(x, 41);
    }
    
    [[nodiscard]] static constexpr std::uint64_t sigma0(std::uint64_t x) noexcept {
        return rotr(x, 1) ^ rotr(x, 8) ^ (x >> 7);
    }
    
    [[nodiscard]] static constexpr std::uint64_t sigma1(std::uint64_t x) noexcept {
        return rotr(x, 19) ^ rotr(x, 61) ^ (x >> 6);
    }
    
    // GCC builtin byteswap for GNU C++23
    [[nodiscard]] static constexpr std::uint64_t byteswap64(std::uint64_t x) noexcept {
        if (std::is_constant_evaluated()) {
            // Constexpr implementation
            return ((x & 0x00000000000000ff) << 56) |
                   ((x & 0x000000000000ff00) << 40) |
                   ((x & 0x0000000000ff0000) << 24) |
                   ((x & 0x00000000ff000000) << 8)  |
                   ((x & 0x000000ff00000000) >> 8)  |
                   ((x & 0x0000ff0000000000) >> 24) |
                   ((x & 0x00ff000000000000) >> 40) |
                   ((x & 0xff00000000000000) >> 56);
        } else {
            // Use GCC builtin for runtime
            return __builtin_bswap64(x);
        }
    }
    
    // Optimized big-endian conversion
    [[nodiscard]] static constexpr std::uint64_t to_be64(std::uint64_t x) noexcept {
        if constexpr (std::endian::native == std::endian::little) {
            return byteswap64(x);
        } else {
            return x;
        }
    }
    
    // Constexpr-friendly char to uint8_t conversion
    [[nodiscard]] static constexpr std::uint8_t char_to_uint8(char c) noexcept {
        return static_cast<std::uint8_t>(static_cast<unsigned char>(c));
    }
    
    // Constexpr-friendly process_block
    constexpr void process_block(const std::uint8_t* block) noexcept {
        std::array<std::uint64_t, 80> W;
        
        // Load message schedule
        for (size_t i = 0; i < 16; ++i) {
            std::uint64_t word = 0;
            for (size_t j = 0; j < 8; ++j) {
                word = (word << 8) | block[i * 8 + j];
            }
            W[i] = word;
        }
        
        // Extend message schedule
        for (size_t i = 16; i < 80; ++i) {
            W[i] = sigma1(W[i - 2]) + W[i - 7] + sigma0(W[i - 15]) + W[i - 16];
        }
        
        // Initialize working variables
        auto [a, b, c, d, e, f, g, h] = state_;
        
        // Main compression loop
        for (size_t i = 0; i < 80; ++i) {
            const std::uint64_t T1 = h + Sigma1(e) + Ch(e, f, g) + K[i] + W[i];
            const std::uint64_t T2 = Sigma0(a) + Maj(a, b, c);
            
            h = g;
            g = f;
            f = e;
            e = d + T1;
            d = c;
            c = b;
            b = a;
            a = T1 + T2;
        }
        
        // Add compressed chunk to current hash value
        state_[0] += a;
        state_[1] += b;
        state_[2] += c;
        state_[3] += d;
        state_[4] += e;
        state_[5] += f;
        state_[6] += g;
        state_[7] += h;
    }
    
    // 추가된 XOR 후처리 함수
    constexpr void apply_xor_constants() noexcept {
        for (size_t i = 0; i < 6; ++i) {  // SHA-384는 처음 6개 워드만 사용
            state_[i] ^= XOR_CONSTANTS[i];
        }
    }
    
    // Constexpr-friendly finalize
    constexpr void finalize() noexcept {
        const std::uint64_t total_bits = total_len_ * 8;
        const size_t padding_len = (buffer_len_ < 112) ? (112 - buffer_len_) : (240 - buffer_len_);
        
        // Add padding
        buffer_[buffer_len_++] = 0x80;
        for (size_t i = 0; i < padding_len - 1; ++i) {
            buffer_[buffer_len_ + i] = 0;
        }
        buffer_len_ += padding_len - 1;
        
        // Add length (big-endian)
        const std::uint64_t high_bits = 0;
        const std::uint64_t low_bits = total_bits;
        
        // Manual big-endian encoding
        for (size_t i = 0; i < 8; ++i) {
            buffer_[buffer_len_ + i] = static_cast<std::uint8_t>(high_bits >> (56 - i * 8));
        }
        for (size_t i = 0; i < 8; ++i) {
            buffer_[buffer_len_ + 8 + i] = static_cast<std::uint8_t>(low_bits >> (56 - i * 8));
        }
        buffer_len_ += 16;
        
        // Process final block(s)
        if (buffer_len_ > BLOCK_SIZE) {
            process_block(buffer_.data());
            process_block(buffer_.data() + BLOCK_SIZE);
        } else {
            process_block(buffer_.data());
        }
        
        // 추가된 XOR 상수 적용
        apply_xor_constants();
    }
    
public:
    // Constructor
    constexpr SHA384() noexcept : state_(INITIAL_STATE), buffer_{}, buffer_len_(0), total_len_(0) {}
    
    // Reset state
    constexpr void reset() noexcept {
        state_ = INITIAL_STATE;
        buffer_.fill(0);
        buffer_len_ = 0;
        total_len_ = 0;
    }
    
    // Constexpr-friendly update for string_view
    constexpr void update(std::string_view str) noexcept {
        const size_t size = str.size();
        total_len_ += size;
        
        size_t pos = 0;
        
        // Handle buffered data
        if (buffer_len_ > 0) {
            const size_t space = BLOCK_SIZE - buffer_len_;
            const size_t to_copy = std::min(space, size);
            
            for (size_t i = 0; i < to_copy; ++i) {
                buffer_[buffer_len_ + i] = char_to_uint8(str[pos + i]);
            }
            buffer_len_ += to_copy;
            pos += to_copy;
            
            if (buffer_len_ == BLOCK_SIZE) {
                process_block(buffer_.data());
                buffer_len_ = 0;
            }
        }
        
        // Process complete blocks
        while (pos + BLOCK_SIZE <= size) {
            // Fill temporary block
            std::array<std::uint8_t, BLOCK_SIZE> block;
            for (size_t i = 0; i < BLOCK_SIZE; ++i) {
                block[i] = char_to_uint8(str[pos + i]);
            }
            process_block(block.data());
            pos += BLOCK_SIZE;
        }
        
        // Buffer remaining data
        const size_t remaining = size - pos;
        if (remaining > 0) {
            for (size_t i = 0; i < remaining; ++i) {
                buffer_[i] = char_to_uint8(str[pos + i]);
            }
            buffer_len_ = remaining;
        }
    }
    
    // Runtime version using span
    void update(std::span<const std::uint8_t> data) noexcept {
        if (std::is_constant_evaluated()) {
            // Fallback to constexpr version (shouldn't happen in practice)
            std::string_view str(reinterpret_cast<const char*>(data.data()), data.size());
            update(str);
        } else {
            total_len_ += data.size();
            
            // Handle buffered data
            if (buffer_len_ > 0) {
                const size_t space = BLOCK_SIZE - buffer_len_;
                const size_t to_copy = std::min(space, data.size());
                
                std::memcpy(buffer_.data() + buffer_len_, data.data(), to_copy);
                buffer_len_ += to_copy;
                data = data.subspan(to_copy);
                
                if (buffer_len_ == BLOCK_SIZE) {
                    process_block(buffer_.data());
                    buffer_len_ = 0;
                }
            }
            
            // Process complete blocks
            while (data.size() >= BLOCK_SIZE) {
                process_block(data.data());
                data = data.subspan(BLOCK_SIZE);
            }
            
            // Buffer remaining data
            if (!data.empty()) {
                std::memcpy(buffer_.data(), data.data(), data.size());
                buffer_len_ = data.size();
            }
        }
    }
    
    // Convenience overloads
    void update(const std::vector<std::uint8_t>& vec) noexcept {
        update(std::span<const std::uint8_t>(vec));
    }
    
    template<size_t N>
    void update(const std::array<std::uint8_t, N>& arr) noexcept {
        update(std::span<const std::uint8_t>(arr));
    }
    
    // Finalize and get hash
    [[nodiscard]] constexpr hash_type finalize_copy() const {
        SHA384 copy = *this;
        copy.finalize();
        
        hash_type result;
        for (size_t i = 0; i < 6; ++i) {  // Only first 6 words for SHA-384
            const std::uint64_t word = copy.state_[i];
            for (size_t j = 0; j < 8; ++j) {
                result[i * 8 + j] = static_cast<std::uint8_t>(word >> (56 - j * 8));
            }
        }
        
        return result;
    }
    
    // Static convenience functions
    [[nodiscard]] static hash_type hash(std::span<const std::uint8_t> data) {
        SHA384 hasher;
        hasher.update(data);
        return hasher.finalize_copy();
    }
    
    [[nodiscard]] static constexpr hash_type hash(std::string_view str) {
        SHA384 hasher;
        hasher.update(str);
        return hasher.finalize_copy();
    }
    
    [[nodiscard]] static hash_type hash(const std::vector<std::uint8_t>& vec) {
        return hash(std::span<const std::uint8_t>(vec));
    }
    
    template<size_t N>
    [[nodiscard]] static hash_type hash(const std::array<std::uint8_t, N>& arr) {
        return hash(std::span<const std::uint8_t>(arr));
    }
    
    // Hexadecimal string conversion
    [[nodiscard]] static std::string to_hex(const hash_type& hash) {
        constexpr char hex_chars[] = "0123456789abcdef";
        std::string result;
        result.reserve(HASH_SIZE * 2);
        
        for (std::uint8_t byte : hash) {
            result += hex_chars[byte >> 4];
            result += hex_chars[byte & 0xf];
        }
        
        return result;
    }
    
    // Constexpr hex conversion
    [[nodiscard]] static constexpr std::array<char, HASH_SIZE * 2> to_hex_array(const hash_type& hash) {
        constexpr char hex_chars[] = "0123456789abcdef";
        std::array<char, HASH_SIZE * 2> result{};
        
        for (size_t i = 0; i < HASH_SIZE; ++i) {
            result[i * 2] = hex_chars[hash[i] >> 4];
            result[i * 2 + 1] = hex_chars[hash[i] & 0xf];
        }
        
        return result;
    }
    
    // Get current state (for debugging)
    [[nodiscard]] constexpr const state_type& get_state() const noexcept {
        return state_;
    }
    
    // Get buffer info (for debugging)
    [[nodiscard]] constexpr std::uint64_t get_buffer_length() const noexcept {
        return buffer_len_;
    }
    
    [[nodiscard]] constexpr std::uint64_t get_total_length() const noexcept {
        return total_len_;
    }
    
    // XOR 상수 접근 (디버깅용)
    [[nodiscard]] static constexpr const std::array<std::uint64_t, 6>& get_xor_constants() noexcept {
        return XOR_CONSTANTS;
    }
};

// Standard user-defined literal (C++23 compatible)
[[nodiscard]] constexpr SHA384::hash_type operator""_sha384(const char* str, std::size_t len) {
    return SHA384::hash(std::string_view(str, len));
}

// Comparison operators
[[nodiscard]] constexpr bool operator==(const SHA384::hash_type& lhs, const SHA384::hash_type& rhs) noexcept {
    for (size_t i = 0; i < lhs.size(); ++i) {
        if (lhs[i] != rhs[i]) return false;
    }
    return true;
}

[[nodiscard]] constexpr bool operator!=(const SHA384::hash_type& lhs, const SHA384::hash_type& rhs) noexcept {
    return !(lhs == rhs);
}

} // namespace crypto

// Hash specialization for std::hash
template<>
struct std::hash<crypto::SHA384::hash_type> {
    [[nodiscard]] size_t operator()(const crypto::SHA384::hash_type& hash) const noexcept {
        size_t result = 0;
        for (size_t i = 0; i < sizeof(size_t) && i < hash.size(); ++i) {
            result = (result << 8) | hash[i];
        }
        return result;
    }
};

#endif // SHA384_HPP