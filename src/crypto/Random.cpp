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
#include <cstdint>
#include <iostream>


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
}


void Random::randomize(QByteArray& ba)
{
    // Generate random data
    QByteArray random(32, 0);  // 32 Bytes seems reasonable as input
    m_rng->randomize(reinterpret_cast<uint8_t*>(random.data()), random.size());

    // Combine randomSeed with entropy from EntropyEventFilter for added randomness
    QByteArray entropy = EntropyEventFilter::instance().getHashedEntropy();
    random.append(entropy);  // another 32 Bytes

    // Initialize SHAKE256 XOF and absorb the seed data
    int outputBits = ba.size() * 8;
    std::unique_ptr<Botan::HashFunction> shake256(Botan::HashFunction::create("SHAKE-256(" + std::to_string(outputBits) + ")"));
    if (!shake256) {
        throw std::runtime_error("Unable to create SHAKE256 object");
    }
    // Absorb the seed data into SHAKE-256
    shake256->update(reinterpret_cast<const uint8_t*>(random.data()), random.size());
    // Generate the output and write directly to `ba`
    Botan::secure_vector<uint8_t> shakeOutput = shake256->final();
    ba = QByteArray(reinterpret_cast<const char*>(shakeOutput.data()), ba.size());
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
        QByteArray byteArray(sizeof(rand), 0);
        this->randomize(byteArray);  // use the internal randomize function
        QDataStream stream(byteArray);
        stream.setByteOrder(QDataStream::LittleEndian);  // Adjust to LittleEndian if needed
        stream >> rand;

    } while (rand > ceil);

    return (rand % limit);
}

quint32 Random::randomUIntRange(quint32 min, quint32 max)
{
    return min + randomUInt(max - min);
}
