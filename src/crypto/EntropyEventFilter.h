/*
*  Copyright (C) 2024 Christian Wengert
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


#ifndef ENTROPY_EVENT_FILTER_H
#define ENTROPY_EVENT_FILTER_H

#include <QEvent>
#include <QMouseEvent>
#include <botan/hash.h>

#define ENTROPY_HASH_FUNCTION "SHA-3(256)"

class EntropyEventFilter : public QObject {
    Q_OBJECT
public:
    static EntropyEventFilter& instance();  // Singleton access method
    void extractEntropyFromEvent(QEvent *event, qint64 currentTime);

    void compressEntropyPool();

    void reseedRngIfNecessary(qint64 currentTime);

    void reseedIfNecessary(qint64 currentTime);

protected:
    bool eventFilter(QObject *obj, QEvent *event) override;

private:
    void getSystemInfo(QString &info);

    void getStartupEntropy(Botan::secure_vector<unsigned char> &systemInfo);

    EntropyEventFilter();                   // Private constructor
    EntropyEventFilter(const EntropyEventFilter&) = delete;             // Disable copy constructor
    EntropyEventFilter& operator=(const EntropyEventFilter&) = delete;  // Disable assignment
    Botan::secure_vector<unsigned char> entropyPool;
    qint64 lastReseedTime = 0;
};

#endif // ENTROPY_EVENT_FILTER_H