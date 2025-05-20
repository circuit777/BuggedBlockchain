from flask import Flask, request, jsonify
from datetime import datetime, timedelta
from threading import RLock

app = Flask(__name__)

# Словарь: адрес ноды -> время последнего обращения
nodes = {}
lock = RLock()

# Время «жизни» записи (если дольше не пингуется — удаляем)
NODE_TTL = timedelta(minutes=5)  # 5 минут

def prune_dead_nodes():
    """Удалить ноды, которые не пингуются дольше NODE_TTL."""
    now = datetime.utcnow()
    with lock:
        to_delete = [addr for addr, ts in nodes.items() if now - ts > NODE_TTL]
        for addr in to_delete:
            del nodes[addr]

@app.route('/nodes', methods=['GET'])
def register_and_list():
    """
    Если передан параметр address, регистрируем ноду.
    Всегда возвращаем список активных нод.
    GET /nodes?address=ip:port или просто /nodes
    """
    addr = request.args.get('address')
    now = datetime.utcnow()

    with lock:
        if addr:
            nodes[addr] = now
        prune_dead_nodes()
        current_nodes = list(nodes.keys())

    # Если нет активных нод, вернуть пустой JSON
    if not current_nodes:
        return jsonify({}), 200

    return jsonify({'nodes': current_nodes}), 200

if __name__ == '__main__':
    # Запуск на всех интерфейсах, порт 5000
    app.run(host='0.0.0.0', port=5000)
