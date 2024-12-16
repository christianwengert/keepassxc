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

#ifndef KEEPASSX_RANDOM_H
#define KEEPASSX_RANDOM_H

#include <QSharedPointer>

#include <botan/rng.h>
#include <botan/hmac_drbg.h>

class Random
{
public:
    static QSharedPointer<Random> instance();

    void randomize(QByteArray& ba) const;
    QByteArray randomArray(int len) const;

    /**
     * Generate a random quint32 in the range [0, @p limit)
     */
    quint32 randomUInt(quint32 limit) const;

    /**
     * Generate a random quint32 in the range [@p min, @p max)
     */
    quint32 randomUIntRange(quint32 min, quint32 max) const;

    void reseedUserRng(Botan::secure_vector<unsigned char> &ba) const;

    void initializeUserRng(Botan::secure_vector<unsigned char> &ba) const;

private:
    explicit Random();
    Q_DISABLE_COPY(Random);

    static QSharedPointer<Random> m_instance;
    QSharedPointer<Botan::RandomNumberGenerator> m_system_rng;
    QSharedPointer<Botan::HMAC_DRBG> m_user_rng;
};

static inline QSharedPointer<Random> randomGen()
{
    return Random::instance();
}

#endif // KEEPASSX_RANDOM_H
