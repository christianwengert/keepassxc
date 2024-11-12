#include "EntropyEventFilter.h"
#include <QCoreApplication>
#include <QDateTime>
#include <QtCore/QCryptographicHash>
#include <chrono>


EntropyEventFilter::EntropyEventFilter() {
    auto h = Botan::HashFunction::create(ENTROPY_HASH_FUNCTION);

    // gather some system info
    auto processID = QCoreApplication::applicationPid();
    qint64 timestamp = QDateTime::currentMSecsSinceEpoch(); // Current timestamp
    QString osVersion = QSysInfo::prettyProductName();
    QString architecture = QSysInfo::currentCpuArchitecture();
    QString machineHostName = QSysInfo::machineHostName();

    // Update the hash function with the gathered parameters
    h->update(reinterpret_cast<const uint8_t*>(ENTROPY_HASH_FUNCTION), sizeof(ENTROPY_HASH_FUNCTION));
    h->update(reinterpret_cast<const uint8_t*>(&processID), sizeof(processID));
    h->update(reinterpret_cast<const uint8_t*>(&timestamp), sizeof(timestamp));
    h->update(reinterpret_cast<const uint8_t*>(osVersion.toUtf8().constData()), osVersion.size());
    h->update(reinterpret_cast<const uint8_t*>(architecture.toUtf8().constData()), architecture.size());
    h->update(reinterpret_cast<const uint8_t*>(machineHostName.toUtf8().constData()), machineHostName.size());

    // Finalize the hash
    Botan::secure_vector<uint8_t> digest = h->final();

    // Convert hash to QByteArray
    entropyPool = QByteArray(reinterpret_cast<const char*>(digest.data()), digest.size());
}


EntropyEventFilter& EntropyEventFilter::instance() {
    static EntropyEventFilter instance;  // Static instance for singleton
    return instance;
}

QByteArray EntropyEventFilter::getHashedEntropy() {
    auto h = Botan::HashFunction::create(ENTROPY_HASH_FUNCTION);
    h->update(reinterpret_cast<const uint8_t*>(entropyPool.constData()), entropyPool.size());

    // Add unique, call-specific values like timestamp or counter
    qint64 timestamp = QDateTime::currentMSecsSinceEpoch();
    h->update(reinterpret_cast<const uint8_t*>(&timestamp), sizeof(timestamp));
    h->update(reinterpret_cast<const uint8_t*>(&callCounter), sizeof(callCounter));
    callCounter++;

    Botan::secure_vector<uint8_t> digest = h->final();

    return {reinterpret_cast<const char*>(digest.data()), static_cast<int>(digest.size())};
}


bool EntropyEventFilter::eventFilter(QObject *obj, QEvent *event) {
    auto h = Botan::HashFunction::create(ENTROPY_HASH_FUNCTION);

    // First, add a timestamp and event type for additional entropy
    qint64 timestamp = QDateTime::currentMSecsSinceEpoch();
    h->update(reinterpret_cast<const uint8_t*>(&timestamp), sizeof(timestamp));
    int eventTypeNumber = static_cast<int>(event->type());
    h->update(reinterpret_cast<const uint8_t*>(&eventTypeNumber), sizeof(eventTypeNumber));

    // Process event data (e.g., mouse, keyboard) and add to hash
    if (event->type() == QEvent::MouseMove ||
        event->type() == QEvent::MouseButtonPress ||
        event->type() == QEvent::MouseButtonRelease ||
        event->type() == QEvent::KeyPress ||
        event->type() == QEvent::KeyRelease) {

        // Add data specific to the event
        switch (event->type()) {
        case QEvent::MouseMove:
        case QEvent::MouseButtonPress:
        case QEvent::MouseButtonRelease: {
            auto* mouseEvent = dynamic_cast<QMouseEvent*>(event);
            int x = mouseEvent->pos().x();
            int y = mouseEvent->pos().y();
            h->update(reinterpret_cast<const uint8_t*>(&x), sizeof(x));
            h->update(reinterpret_cast<const uint8_t*>(&y), sizeof(y));
            int gx = mouseEvent->globalX();
            int gy = mouseEvent->globalY();
            h->update(reinterpret_cast<const uint8_t*>(&gx), sizeof(gx));
            h->update(reinterpret_cast<const uint8_t*>(&gy), sizeof(gy));
            break;
        }
        case QEvent::KeyPress:
        case QEvent::KeyRelease: {
            auto* keyEvent = dynamic_cast<QKeyEvent*>(event);
            int key = keyEvent->key();
            h->update(reinterpret_cast<const uint8_t*>(&key), sizeof(key));
            break;
        }
        default:
            break;
        }
    }

    // Update the entropy pool only when new data is added
    h->update(reinterpret_cast<const uint8_t*>(entropyPool.constData()), entropyPool.size());
    Botan::secure_vector<uint8_t> digest = h->final();

    // set new entropy pool with new entropy and hash of last entropy
    for (int i = 0; i < static_cast<int>(digest.size()); i++) {
        entropyPool[i] = static_cast<char>(digest[i] ^ entropyPool[i]);
    }

    return QObject::eventFilter(obj, event);
}