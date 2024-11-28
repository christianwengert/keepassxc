#include "EntropyEventFilter.h"
#include <QCoreApplication>
#include <QDateTime>
#include "Random.h"


EntropyEventFilter::EntropyEventFilter() {
    const auto h = Botan::HashFunction::create(ENTROPY_HASH_FUNCTION);

    // gather some system info
    const auto processID = QCoreApplication::applicationPid();
    const qint64 timestamp = QDateTime::currentMSecsSinceEpoch(); // Current timestamp
    const QString osVersion = QSysInfo::prettyProductName();
    const QString architecture = QSysInfo::currentCpuArchitecture();
    const QString machineHostName = QSysInfo::machineHostName();

    // Update the hash function with the gathered parameters
    h->update(reinterpret_cast<const uint8_t*>(ENTROPY_HASH_FUNCTION), sizeof(ENTROPY_HASH_FUNCTION));
    h->update(reinterpret_cast<const uint8_t*>(&processID), sizeof(processID));
    h->update(reinterpret_cast<const uint8_t*>(&timestamp), sizeof(timestamp));
    h->update(reinterpret_cast<const uint8_t*>(osVersion.toUtf8().constData()), osVersion.size());
    h->update(reinterpret_cast<const uint8_t*>(architecture.toUtf8().constData()), architecture.size());
    h->update(reinterpret_cast<const uint8_t*>(machineHostName.toUtf8().constData()), machineHostName.size());

    // Finalize the hash
    entropyPool = h->final();
    // reseed the secondary RNG
    Random::instance()->reseed_user_rng(entropyPool);
}


EntropyEventFilter& EntropyEventFilter::instance() {
    static EntropyEventFilter instance;  // Static instance for singleton
    return instance;
}


bool EntropyEventFilter::eventFilter(QObject *obj, QEvent *event) {

    // Collect raw event data as entropy
    const qint64 currentTime = QDateTime::currentMSecsSinceEpoch();
    const auto* currentTimeData = reinterpret_cast<const unsigned char*>(&currentTime);

    entropyPool.insert(entropyPool.end(), currentTimeData, currentTimeData + sizeof(currentTime));

    const int eventTypeNumber = event->type();
    auto eventTypeData = reinterpret_cast<const unsigned char*>(&eventTypeNumber);
    entropyPool.insert(entropyPool.end(), eventTypeData, eventTypeData + sizeof(currentTime));

    if (event->type() == QEvent::MouseMove ||
        event->type() == QEvent::MouseButtonPress ||
        event->type() == QEvent::MouseButtonRelease ||
        event->type() == QEvent::KeyPress ||
        event->type() == QEvent::KeyRelease) {

        switch (event->type()) {
            case QEvent::MouseMove:
            case QEvent::MouseButtonPress:
            case QEvent::MouseButtonRelease: {
                auto* mouseEvent = dynamic_cast<QMouseEvent*>(event);
                const int x = mouseEvent->pos().x();
                const int y = mouseEvent->pos().y();
                const auto* xData = reinterpret_cast<const unsigned char*>(&x);
                const auto* yData = reinterpret_cast<const unsigned char*>(&y);
                entropyPool.insert(entropyPool.end(), xData, xData + sizeof(x));
                entropyPool.insert(entropyPool.end(), yData, yData + sizeof(y));
                break;
            }
            case QEvent::KeyPress:
            case QEvent::KeyRelease: {
                const auto* keyEvent = dynamic_cast<QKeyEvent*>(event);
                const int key = keyEvent->key();
                const auto* keyData = reinterpret_cast<const unsigned char*>(&key);
                entropyPool.insert(entropyPool.end(), keyData, keyData + sizeof(key));
                break;
            }
            default:
                break;
        }
    }

    // Define thresholds
    constexpr size_t POOL_CAP = 4096; // Maximum 4 KB for the entropy pool
    constexpr qint64 MIN_RESEED_INTERVAL_MS = 5000; //

    // Hash excess entropy when the pool exceeds the cap
    if (entropyPool.size() > POOL_CAP) {
        const auto hash = Botan::HashFunction::create(ENTROPY_HASH_FUNCTION);
        if (hash) {
            // Hash the excess entropy to condense it
            hash->update(entropyPool.data(), entropyPool.size());
            const auto condensedEntropy = hash->final();

            // Replace the pool with the condensed entropy
            entropyPool.clear();
            entropyPool.insert(entropyPool.end(), condensedEntropy.begin(), condensedEntropy.end());
        }
    }

    // Reseed the PRNG only when necessary
    if (entropyPool.size() >= POOL_CAP / 2 && (currentTime - lastReseedTime) >= MIN_RESEED_INTERVAL_MS) {
        // we want more output this time
        const auto hash = Botan::HashFunction::create("SHA-3(512)");
        hash->update(entropyPool.data(), entropyPool.size());

        // Get the fixed 512-bit output
        const auto sha3Output = hash->final();

        // Split the output into two 256-bit parts
        Botan::secure_vector<uint8_t> seedRNG(sha3Output.begin(), sha3Output.begin() + 32);
        Botan::secure_vector<uint8_t> retainedEntropy(sha3Output.begin() + 32, sha3Output.end());

        // Reseed the RNG with the first part
        Random::instance()->reseed_user_rng(seedRNG);

        // Replace the entropy pool with the second part
        entropyPool.clear();
        entropyPool.insert(entropyPool.end(), retainedEntropy.begin(), retainedEntropy.end());

        lastReseedTime = currentTime;
    }

    return QObject::eventFilter(obj, event);
}