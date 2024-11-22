from shodan import Shodan

api = Shodan("<API-SHODAN>")

try:
    info = api.info()
    print(f"Plano: {info['plan']}, Requests restantes: {info['query_credits']}")
except Exception as e:
    print(f"Erro na API do Shodan: {e}")from shodan import Shodan

api = Shodan("<API-SHODAN>")

try:
    info = api.info()
    print(f"Plano: {info['plan']}, Requests restantes: {info['query_credits']}")
except Exception as e:
    print(f"Erro na API do Shodan: {e}")