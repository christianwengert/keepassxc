#include "EntropyEventFilter.h"

#include <iostream>
#include <QCoreApplication>
#include <QDateTime>
#include <QMouseEvent>
#include <botan/hash.h>
#include <QtCore/qelapsedtimer.h>
#include <QtCore/qfileinfo.h>

#include "Random.h"


// classical Shannon Entropy
double calculateShannonEntropy(const Botan::secure_vector<unsigned char>& data) {
    std::array<unsigned char, 256> frequencies = {0};
    for (const auto byte : data) {
        frequencies[byte]++;
    }
    double entropy = 0.0;
    for (const auto count : frequencies) {
        if (count > 0) {
            const double p = static_cast<double>(count) / static_cast<double>(data.size());
            entropy -= p * std::log2(p);
        }
    }
    return entropy;
}


// Min Entropy: worst-case predictability
double calculateMinEntropy(const Botan::secure_vector<unsigned char>& data) {
    std::array<unsigned char, 256> frequencies = {0};
    for (const auto byte : data) {
        frequencies[byte]++;
    }
    const auto maxCount = *std::ranges::max_element(frequencies);
    const double maxProbability = static_cast<double>(maxCount) / static_cast<double>(data.size());
    return -std::log2(maxProbability);
}


void EntropyEventFilter::getStartupEntropy(Botan::secure_vector<uint8_t> &systemInfo) {
    // Gather some available system info
    QElapsedTimer timer;
    timer.start();

    // get current timestamp
    const qint64 timestamp = QDateTime::currentMSecsSinceEpoch(); // Current timestamp
    // PID
    const auto processID = QCoreApplication::applicationPid();

    // app data
    QString info;
    info += QCoreApplication::applicationVersion();
    info += QCoreApplication::applicationFilePath();
    info += QCoreApplication::organizationDomain();
    info += QCoreApplication::organizationName();
    // sys data
    info += QSysInfo::currentCpuArchitecture();
    info += QSysInfo::buildCpuArchitecture();
    info += QSysInfo::machineHostName();
    info += QSysInfo::buildAbi();
    info += QSysInfo::kernelType();
    info += QSysInfo::kernelVersion();
    info += QSysInfo::productType();
    info += QSysInfo::productVersion();
    info += QSysInfo::prettyProductName();
    info += QSysInfo::machineUniqueId();
    const auto infoUtf8 = info.toUtf8();

    // some more sources
    const QFileInfo fileInfo(QCoreApplication::applicationFilePath());
    const auto fileTime = fileInfo.lastModified().toMSecsSinceEpoch();

    // Memory address entropy
    int dummyVariable;
    const auto memoryAddress = reinterpret_cast<unsigned long>(&dummyVariable);

    // Append raw data directly into entropyPool
    systemInfo.insert(systemInfo.end(),
                      reinterpret_cast<const uint8_t*>(&processID),
                      reinterpret_cast<const uint8_t*>(&processID) + sizeof(processID));
    systemInfo.insert(systemInfo.end(),
                      reinterpret_cast<const uint8_t*>(&timestamp),
                      reinterpret_cast<const uint8_t*>(&timestamp) + sizeof(timestamp));
    systemInfo.insert(systemInfo.end(),
                          reinterpret_cast<const uint8_t*>(&memoryAddress),
                          reinterpret_cast<const uint8_t*>(&memoryAddress) + sizeof(memoryAddress));
    systemInfo.insert(systemInfo.end(),
                      reinterpret_cast<const uint8_t*>(&fileTime),
                      reinterpret_cast<const uint8_t*>(&fileTime) + sizeof(fileTime));
    const qint64 operationDuration = timer.nsecsElapsed();
    systemInfo.insert(systemInfo.end(),
                      reinterpret_cast<const uint8_t*>(&operationDuration),
                      reinterpret_cast<const uint8_t*>(&operationDuration) + sizeof(operationDuration));
    // now add the big string
    systemInfo.insert(systemInfo.end(),
                      reinterpret_cast<const uint8_t*>(infoUtf8.constData()),
                      reinterpret_cast<const uint8_t*>(infoUtf8.constData()) + infoUtf8.size());

}


EntropyEventFilter::EntropyEventFilter() {
    Botan::secure_vector<uint8_t> systemInfo;
    getStartupEntropy(systemInfo);

    const auto hash = Botan::HashFunction::create("SHA-3(256)");
    if (hash) {
        // Hash the excess entropy to condense it
        hash->update(systemInfo.data(), systemInfo.size());
        Botan::secure_vector<unsigned char> condensedEntropy = hash->final();
        Random::instance()->initializeUserRng(condensedEntropy);
    } else {
        throw std::invalid_argument("EntropyEventFilter::EntropyEventFilter()");
    }
}


EntropyEventFilter &EntropyEventFilter::instance() {
    static EntropyEventFilter instance;  // Static instance for singleton
    return instance;
}


bool EntropyEventFilter::eventFilter(QObject *obj, QEvent *event) {
    // Collect raw event data as entropy
    const qint64 currentTime = QDateTime::currentMSecsSinceEpoch();

    if (event->type() == QEvent::KeyPress ||
        event->type() == QEvent::KeyRelease ||
        event->type() == QEvent::MouseButtonPress ||
        event->type() == QEvent::MouseButtonRelease ||
        event->type() == QEvent::MouseMove ) {

        const auto *currentTimeData = reinterpret_cast<const unsigned char *>(&currentTime);
        entropyPool.insert(entropyPool.end(), currentTimeData, currentTimeData + sizeof(currentTime));

        // use all events and a timestamp
        const int eventTypeNumber = event->type();
        const auto eventTypeData = reinterpret_cast<const unsigned char *>(&eventTypeNumber);
        entropyPool.insert(entropyPool.end(), eventTypeData, eventTypeData + sizeof(currentTime));

        static QPoint lastMousePos;
        static qint64 lastMouseTime = 0;
        static qint64 lastKeyTime = 0;

        // gather entropy for specific user events
        switch (event->type()) {
            case QEvent::MouseMove:
            case QEvent::MouseButtonPress:
            case QEvent::MouseButtonRelease: {
                const auto *mouseEvent = dynamic_cast<QMouseEvent *>(event);
                const int x = mouseEvent->pos().x();
                const int y = mouseEvent->pos().y();
                const auto *xData = reinterpret_cast<const unsigned char *>(&x);
                const auto *yData = reinterpret_cast<const unsigned char *>(&y);
                entropyPool.insert(entropyPool.end(), xData, xData + sizeof(x));
                entropyPool.insert(entropyPool.end(), yData, yData + sizeof(y));
                if (lastMouseTime > 0) {
                    // also add acceleration and speed
                    const auto timeDelta = static_cast<float>(currentTime - lastMouseTime);
                    const int dx = x - lastMousePos.x();
                    const int dy = y - lastMousePos.y();
                    const float distance = std::sqrtf(static_cast<float>(dx * dx + dy * dy));
                    const float speed = distance / (timeDelta);
                    const float acceleration = speed / timeDelta;

                    const auto *speedData = reinterpret_cast<const unsigned char *>(&speed);
                    const auto *accelData = reinterpret_cast<const unsigned char *>(&acceleration);
                    entropyPool.insert(entropyPool.end(), speedData, speedData + sizeof(speed));
                    entropyPool.insert(entropyPool.end(), accelData, accelData + sizeof(acceleration));
                }

                lastMousePos = mouseEvent->pos();
                lastMouseTime = currentTime;
                break;
            }
            case QEvent::KeyPress:
            case QEvent::KeyRelease: {
                const auto *keyEvent = dynamic_cast<QKeyEvent *>(event);
                const auto key = static_cast<const unsigned char>(keyEvent->key());
                entropyPool.push_back(key);
                if (lastKeyTime > 0) {
                    const qint64 timeDelta = currentTime - lastKeyTime;
                    const auto *timeDeltaData = reinterpret_cast<const unsigned char *>(&timeDelta);
                    entropyPool.insert(entropyPool.end(), timeDeltaData, timeDeltaData + sizeof(timeDelta));
                }
                lastKeyTime = currentTime;
                break;
            }
            default:
                break;
        }

        // Define thresholds
        constexpr size_t POOL_CAP = 4096; // Maximum 4 KB for the entropy pool
        constexpr qint64 MIN_RESEED_INTERVAL_MS = 5000; //

        if (entropyPool.size() > POOL_CAP) { // limit maximum growth of entropy pool
            const auto hash = Botan::HashFunction::create("SHA-3(256)");
            if (hash) {
                // Hash the excess entropy to condense it
                hash->update(entropyPool.data(), entropyPool.size());
                const auto condensedEntropy = hash->final();
                // Replace the pool with the condensed entropy
                entropyPool.clear();
                entropyPool.insert(entropyPool.end(), condensedEntropy.begin(), condensedEntropy.end());
            }
        }

        // Reseed the PRNG only every 5 seconds and if we filled the pool
        // if (entropyPool.size() >= POOL_CAP / 2 && (currentTime - lastReseedTime) >= MIN_RESEED_INTERVAL_MS) {
        // Reseed the PRNG only every 5 seconds and if we have enough entropy in the pool
        const double shannonEntropy = calculateShannonEntropy(entropyPool) * entropyPool.size();
        const double minEntropy = calculateMinEntropy(entropyPool) * entropyPool.size();

        constexpr int securityLevel = 256;

        if (shannonEntropy > securityLevel &&
            minEntropy > securityLevel &&
            currentTime - lastReseedTime >= MIN_RESEED_INTERVAL_MS) {
            // estimate the entropy over the whole pool (in bits)

            std::cout << "reseed entropy: " << entropyPool.size() << " " << " " << shannonEntropy << " " << minEntropy << std::endl;

            // Reseed the RNG with the hash of the pool
            // ensures any biases or patterns in the raw entropy are removed
            // also ensures that if the pool becomes too large for the RNG to process
            const auto hash = Botan::HashFunction::create("SHA-3(256)");
            hash->update(entropyPool.data(), entropyPool.size());
            auto digest = hash->final();
            Random::instance()->reseedUserRng(digest);

            entropyPool.clear();

            lastReseedTime = currentTime;
        }
    }

    return QObject::eventFilter(obj, event);
}
