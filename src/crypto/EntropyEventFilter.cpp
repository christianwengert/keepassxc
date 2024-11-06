#include "EntropyEventFilter.h"
#include <QtCore/QCryptographicHash>
#include <QDateTime>


EntropyEventFilter::EntropyEventFilter() : hash(Botan::HashFunction::create("SHA-256")), counter(0)  {}

EntropyEventFilter& EntropyEventFilter::instance() {
    static EntropyEventFilter instance;  // Static instance for singleton
    return instance;
}

QByteArray EntropyEventFilter::getHashedEntropy() {
    // add the counter for having different results on every call
    hash->update(reinterpret_cast<const uint8_t*>(&counter), sizeof(counter));
    Botan::secure_vector<uint8_t> digest = hash->final();
    hash->clear();          // after final no more computation possible until clear
    hash->update(digest);  // feed last hash value into hash
    return QByteArray(reinterpret_cast<const char*>(digest.data()), static_cast<int>(digest.size()));
}


bool EntropyEventFilter::eventFilter(QObject *obj, QEvent *event) {
    if (event->type() == QEvent::MouseMove ||
        event->type() == QEvent::MouseButtonPress ||
        event->type() == QEvent::MouseButtonRelease ||
        event->type() == QEvent::KeyPress ||
        event->type() == QEvent::KeyRelease) {

        // first add a timestamp
        qint64 timestamp = QDateTime::currentMSecsSinceEpoch();
        hash->update(reinterpret_cast<const uint8_t*>(&timestamp), sizeof(timestamp));

        // Secondly we hash some extra data iof available (mouse and keyboard)
        switch (event->type()) {
        case QEvent::MouseMove:
        case QEvent::MouseButtonPress:
        case QEvent::MouseButtonRelease: {
            auto* mouseEvent = dynamic_cast<QMouseEvent*>(event);
            int x = mouseEvent->pos().x();
            int y = mouseEvent->pos().y();
            hash->update(reinterpret_cast<const uint8_t*>(&x), sizeof(x));
            hash->update(reinterpret_cast<const uint8_t*>(&y), sizeof(y));
            break;
        }
        case QEvent::KeyPress:
        case QEvent::KeyRelease: {
            auto* keyEvent = dynamic_cast<QKeyEvent*>(event);
            int key = keyEvent->key();
            hash->update(reinterpret_cast<const uint8_t*>(&key), sizeof(key));
            break;
        }
        default:
            break;
        }
    }
    return QObject::eventFilter(obj, event);
}