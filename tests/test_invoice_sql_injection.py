
import pytest
import requests
import random


BASE_URL = "http://localhost:5000"
API_INVOICES_URL = f"{BASE_URL}/invoices"


@pytest.fixture(scope="module")
def test_user():
    """Crea un usuario de prueba y retorna sus credenciales y token."""
    i = random.randint(1000, 999999)
    username = f'sqltest_user{i}'
    email = f'{username}@test.com'
    password = 'SecurePass123!'
    
    # Crear un nuevo usuario
    response = requests.post(
        f"{BASE_URL}/users",
        json={
            "username": username,
            "password": password,
            "email": email,
            "first_name": "SQL",
            "last_name": "Test"
        }
    )
    assert response.status_code == 201, f"Failed to create user: {response.text}"
    
    # Login para obtener token
    login_response = requests.post(
        f"{BASE_URL}/login",
        json={
            "username": username,
            "password": password
        }
    )
    assert login_response.status_code == 200, f"Failed to login: {login_response.text}"
    
    token = login_response.json().get('token')
    user_id = login_response.json().get('userId')
    
    return {
        'username': username,
        'token': token,
        'user_id': user_id,
        'headers': {'Authorization': f'Bearer {token}'}
    }


class TestSQLInjectionListInvoices:
    
    def test_list_invoices_works_normally(self, test_user):
        # Verificar que el endpoint funciona correctamente sin inyección.
        response = requests.get(API_INVOICES_URL, headers=test_user['headers'])
        assert response.status_code == 200
        assert isinstance(response.json(), list)
    
    def test_sql_injection_union_select_blocked(self, test_user):
        # Validar que UNION SELECT attacks están bloqueadas.
        payloads = [
            "' UNION SELECT * FROM users--",
            "' UNION SELECT id, userId, amount, dueDate, 'hacked' FROM invoices--",
        ]
        
        for payload in payloads:
            response = requests.get(
                API_INVOICES_URL,
                params={"status": payload},
                headers=test_user['headers']
            )
            
            assert response.status_code in [200, 400, 422]
            
            if response.status_code == 200:
                data = response.json()
                assert isinstance(data, list)
                # Verificar que no retorna datos de otros usuarios
                for invoice in data:
                    if 'userId' in invoice:
                        assert str(invoice['userId']) == str(test_user['user_id']), \
                            "SQL Injection: Datos de otros usuarios accedidos"
    
    def test_sql_injection_or_condition_blocked(self, test_user):
        # Validar que condiciones OR maliciosas están bloqueadas.
        payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "admin' OR '1'='1'--",
        ]
        
        for payload in payloads:
            response = requests.get(
                API_INVOICES_URL,
                params={"status": payload},
                headers=test_user['headers']
            )
            
            assert response.status_code in [200, 400, 422]
            
            if response.status_code == 200:
                data = response.json()
                # Solo debe retornar facturas del usuario autenticado
                for invoice in data:
                    if 'userId' in invoice:
                        assert str(invoice['userId']) == str(test_user['user_id']), \
                            "SQL Injection: Bypass de autorización detectado"
    
    def test_sql_injection_dangerous_commands_blocked(self, test_user):
        # Validar que comandos SQL peligrosos están bloqueados  
        payloads = [
            "'; DROP TABLE invoices--",
            "'; DELETE FROM invoices--",
            "'; UPDATE invoices SET status='hacked'--",
        ]
        
        for payload in payloads:
            response = requests.get(
                API_INVOICES_URL,
                params={"status": payload},
                headers=test_user['headers']
            )
            
            assert response.status_code in [200, 400, 422]
            
            # Verificar que las facturas todavía existen y no fueron modificadas
            verification = requests.get(API_INVOICES_URL, headers=test_user['headers'])
            assert verification.status_code == 200
            
            # Verificar que no hay facturas con status 'hacked'
            if verification.status_code == 200:
                invoices = verification.json()
                for invoice in invoices:
                    assert invoice.get('status') != 'hacked', \
                        "SQL Injection: Datos modificados"


class TestSQLInjectionGetInvoice:
    # Tests  para validar protección contra SQL injection en GET /invoices/:id
    
    def test_get_invoice_works_normally(self, test_user):
        # Verificar que el endpoint funciona correctamente sin inyección.
        list_response = requests.get(API_INVOICES_URL, headers=test_user['headers'])
        
        if list_response.status_code == 200 and list_response.json():
            invoices = list_response.json()
            if invoices:
                invoice_id = invoices[0]['id']
                response = requests.get(
                    f"{API_INVOICES_URL}/{invoice_id}",
                    headers=test_user['headers']
                )
                assert response.status_code in [200, 404]
    
    def test_sql_injection_in_invoice_id_blocked(self, test_user):
        # Validar que inyección SQL en el parámetro ID está bloqueada.
        payloads = [
            "1' OR '1'='1",
            "1' UNION SELECT * FROM users--",
            "1'; DROP TABLE invoices--",
        ]
        
        for payload in payloads:
            response = requests.get(
                f"{API_INVOICES_URL}/{payload}",
                headers=test_user['headers']
            )
            
            assert response.status_code in [200, 400, 404, 422, 500]
            
            if response.status_code == 200:
                data = response.json()
                if isinstance(data, dict):
                    # No debe contener información sensible de otros usuarios
                    assert 'username' not in data
                    assert 'password' not in data
                    if 'userId' in data:
                        assert str(data['userId']) == str(test_user['user_id']), \
                            "SQL Injection: Acceso a factura de otro usuario"
            
            # Verificar que la tabla no fue eliminada
            verification = requests.get(API_INVOICES_URL, headers=test_user['headers'])
            assert verification.status_code == 200


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
