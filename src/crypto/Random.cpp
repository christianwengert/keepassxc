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

#include "EntropyEventFilter.h"
#include "core/Global.h"

#include <QSharedPointer>

#include <botan/system_rng.h>
#include <botan/chacha_rng.h>
#include <cstdint>

#include <iostream>
#include <botan/p11.h>


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
    m_rng.reset(new Botan::System_RNG);
#else
    m_rng.reset(new Botan::Autoseeded_RNG);
#endif
    m_rng2.reset(new Botan::ChaCha_RNG);
}


    void Random::randomize(QByteArray& ba)
    {
        // Generate random data
        QByteArray random(ba);
        m_rng->randomize(reinterpret_cast<uint8_t*>(random.data()), random.size());

        QByteArray finalOutput;
        int outputSize = ba.size();
        auto start = random.begin();
        int contextCounter = 0;  // Initialize a context counter

        while (finalOutput.size() < outputSize) {

            std::unique_ptr<Botan::MessageAuthenticationCode> hmac(Botan::MessageAuthenticationCode::create("HMAC(SHA-256)"));
            auto blockSize = hmac->output_length();
            if (!hmac) {
                throw std::runtime_error("Unable to create HMAC object");
            }

            QByteArray hmacKey = EntropyEventFilter::instance().getHashedEntropy();
            std::cout << "HMAC Key " << hmacKey.toHex().toStdString() << std::endl;
            // Set the HMAC key (output of first RNG)
            hmac->set_key(reinterpret_cast<const uint8_t*>(hmacKey.data()), hmacKey.size());

            // Create a context that includes a counter to ensure uniqueness
            QByteArray contextData;
            int dataSize = std::min(static_cast<int>(hmacKey.size()), static_cast<int>(random.end() - start));
            contextData.append(reinterpret_cast<const char*>(start), dataSize);
            contextData.append(reinterpret_cast<const char*>(&contextCounter), sizeof(contextCounter));  // Add counter

            // HMAC the RNG data with the context
            hmac->update(reinterpret_cast<const uint8_t*>(contextData.data()), contextData.size());
            Botan::secure_vector<uint8_t> hmacResult = hmac->final();
            finalOutput.append(QByteArray::fromRawData(reinterpret_cast<const char*>(hmacResult.data()), hmacResult.size()));

            contextCounter++;  // Increment the counter for each iteration
            start += blockSize;
        }

        ba = finalOutput.left(outputSize);  // Truncate to match requested size
    }

QByteArray Random::randomArray(int len)
{
    QByteArray ba(len, '\0');
    randomize(ba);
    return ba;
}

quint32 Random::randomUInt(quint32 limit)
{
    Q_ASSERT(limit <= QUINT32_MAX);
    if (limit == 0) {
        return 0;
    }

    quint32 rand;
    const quint32 ceil = QUINT32_MAX - (QUINT32_MAX % limit) - 1;

    // To avoid modulo bias make sure rand is below the largest number where rand%limit==0
    do {
        // It seems cleaner to call the Random.randomize, so the Botan::RNG.randomize is only called at one single place
        QByteArray byteArray(sizeof(rand), 0);
        this->randomize(byteArray);
        rand = *reinterpret_cast<const quint32*>(byteArray.constData());
    } while (rand > ceil);

    return (rand % limit);
}

quint32 Random::randomUIntRange(quint32 min, quint32 max)
{
    return min + randomUInt(max - min);
}
