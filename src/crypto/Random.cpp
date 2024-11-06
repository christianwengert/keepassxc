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
#include <vector>
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
    // reseed m_rng2
    QByteArray entropy = EntropyEventFilter::instance().getHashedEntropy();
    std::vector<uint8_t> entropyData(entropy.begin(), entropy.end());
    m_rng2->add_entropy(entropyData.data(), entropyData.size());
    std::cout << "Reseed " << entropy.toHex().toStdString() << std::endl;

    // get randoms from each RNG
    QByteArray random1(ba);
    QByteArray random2(ba);
    m_rng->randomize(reinterpret_cast<uint8_t*>(random1.data()), random1.size());
    m_rng2->randomize(reinterpret_cast<uint8_t*>(random2.data()), random2.size());

    // mix with XOR
    for (int i = 0; i < random1.size(); ++i) {
        ba[i] = static_cast<char>(random1[i] ^ random2[i]);
    }
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
