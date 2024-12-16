/*
 *  Copyright (C) 2010 Felix Geyer <debfx@fobos.de>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 2 or (at your option)
 *  version 3 of the License.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "Random.h"
#include "core/Global.h"
#include <QSharedPointer>
#include <botan/system_rng.h>
#include <botan/hmac_drbg.h>
#include <botan/hash.h>




QSharedPointer<Random> Random::m_instance;

QSharedPointer<Random> Random::instance()
{
    if (!m_instance) {
        m_instance.reset(new Random());
    }
    return m_instance;
}

Random::Random()
{
#ifdef BOTAN_HAS_SYSTEM_RNG
    m_system_rng.reset(new Botan::System_RNG);
#else
    m_system_rng.reset(new Botan::Autoseeded_RNG);
#endif
    // in any case initialize the secondary rng
    m_user_rng.reset(new Botan::HMAC_DRBG("SHA-3(256)")); // we will reseed this ourselves
}


void Random::reseedUserRng(Botan::secure_vector<unsigned char> &ba) const {
    if (!m_user_rng->accepts_input()) {
        throw std::runtime_error("Secondary RNG does not accept external entropy");
    }
    if (!m_user_rng->is_seeded()) {
        throw std::runtime_error("Secondary RNG is not seeded");
    }
    m_user_rng->add_entropy(ba);  // ba will be hmac'd and thus hashed in the RNGs update function
}

void Random::initializeUserRng(Botan::secure_vector<unsigned char> &ba) const {

    if (!m_user_rng->is_seeded()) {
        // Add system random to the provided system entropy data
        Botan::secure_vector<unsigned char> systemRandom(32, '\0'); // Create a 32 Byte QByteArray
        m_system_rng->randomize(systemRandom.data(), systemRandom.size());

        // Combine user-provided entropy with system randomness
        Botan::secure_vector<unsigned char> combinedEntropy(ba.begin(), ba.end()); // Start with user-provided entropy
        combinedEntropy.insert(combinedEntropy.end(), systemRandom.begin(), systemRandom.end()); // Append system randomness

        // Seed the RNG with the combined entropy
        m_user_rng->initialize_with(combinedEntropy);
    }
}


void Random::randomize(QByteArray& ba) const {
    QByteArray systemRandom(ba.size(), 0);
    m_system_rng->randomize(reinterpret_cast<unsigned char*>(systemRandom.data()), systemRandom.size());

    // Combine randomSeed with entropy from EntropyEventFilter for added randomness
    QByteArray userRandom(ba.size(), 0);  // another 32 Bytes for the seed, from a different RNG
    m_user_rng->randomize(reinterpret_cast<unsigned char*>(userRandom.data()), userRandom.size());

    QByteArray seed;
    seed.append(userRandom);
    seed.append(systemRandom);

    // Initialize SHAKE256 XOF for mixing
    const int outputBits = ba.size() * 8;
    const std::unique_ptr shake256(Botan::HashFunction::create("SHAKE-256(" + std::to_string(outputBits) + ")"));
    if (!shake256) {
        throw std::runtime_error("Unable to create SHAKE256 object");
    }
    // Absorb the seed data into SHAKE-256
    shake256->update(reinterpret_cast<const unsigned char*>(seed.data()), seed.size());
    // Generate the output and write directly to `ba`
    const Botan::secure_vector<unsigned char> shakeOutput = shake256->final();
    ba = QByteArray(reinterpret_cast<const char*>(shakeOutput.data()), ba.size());
}


QByteArray Random::randomArray(int len) const {
    QByteArray ba(len, '\0');
    randomize(ba);
    return ba;
}

quint32 Random::randomUInt(quint32 limit) const {
    Q_ASSERT(limit <= QUINT32_MAX);
    if (limit == 0) {
        return 0;
    }

    quint32 rand;
    const quint32 ceil = QUINT32_MAX - (QUINT32_MAX % limit) - 1;

    // To avoid modulo bias make sure rand is below the largest number where rand%limit==0
    do {
        QByteArray byteArray(sizeof(rand), 0);
        this->randomize(byteArray);  // use the internal randomize function, so the m_rng is called only in one place
        rand = *reinterpret_cast<const qint32*>(byteArray.constData());

    } while (rand > ceil);

    return rand % limit;
}

quint32 Random::randomUIntRange(quint32 min, quint32 max) const {
    return min + randomUInt(max - min);
}
