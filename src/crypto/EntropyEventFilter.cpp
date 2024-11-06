#include "EntropyEventFilter.h"
#include <QtCore/QCryptographicHash>
#include <QDateTime>


EntropyEventFilter::EntropyEventFilter() : hash(QCryptographicHash::Sha256) {}

EntropyEventFilter& EntropyEventFilter::instance() {
    static EntropyEventFilter instance;  // Static instance for singleton
    return instance;
}

QByteArray EntropyEventFilter::getHashedEntropy() {
    // Return the current 32-byte hash and reset for further hashing
    qint64 timestamp = QDateTime::currentMSecsSinceEpoch();
    hash.addData(reinterpret_cast<const char*>(&timestamp), sizeof(timestamp));
    QByteArray digest = hash.result();   // Get the current hash
//    hash.reset();                        // Reset the hash to start fresh
    return digest;
}


bool EntropyEventFilter::eventFilter(QObject *obj, QEvent *event) {
    if (event->type() == QEvent::MouseMove ||
        event->type() == QEvent::MouseButtonPress ||
        event->type() == QEvent::MouseButtonRelease ||
        event->type() == QEvent::KeyPress ||
        event->type() == QEvent::KeyRelease) {

        // first add a timestamp
        qint64 timestamp = QDateTime::currentMSecsSinceEpoch();
        hash.addData(reinterpret_cast<const char*>(&timestamp), sizeof(timestamp));

        // Secondly we hash some extra data iof available (mouse and keyboard)
        switch (event->type()) {
        case QEvent::MouseMove:
        case QEvent::MouseButtonPress:
        case QEvent::MouseButtonRelease: {
            auto* mouseEvent = dynamic_cast<QMouseEvent*>(event);
            int x = mouseEvent->pos().x();
            int y = mouseEvent->pos().y();
            hash.addData(reinterpret_cast<const char*>(&x), sizeof(x));
            hash.addData(reinterpret_cast<const char*>(&y), sizeof(y));
            break;
        }
        case QEvent::KeyPress:
        case QEvent::KeyRelease: {
            auto* keyEvent = dynamic_cast<QKeyEvent*>(event);
            int key = keyEvent->key();
            hash.addData(reinterpret_cast<const char*>(&key), sizeof(key));
            break;
        }
        default:
            break;
        }
    }
    return QObject::eventFilter(obj, event);
}