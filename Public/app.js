
const vistaAuth = document.getElementById('vista-auth');
const vistaViajes = document.getElementById('vista-viajes');

if (vistaAuth) {
    const btnAccion = document.getElementById('btn-accion');
    const toggleAuth = document.getElementById('toggle-auth');
    const tituloAuth = document.getElementById('titulo-auth');
    let esLogin = true;

    // Verificar sesión guardada
    if (localStorage.getItem('token')) mostrarMisViajes();

    // Cambiar entre Login y Registro
    toggleAuth.addEventListener('click', (e) => {
        e.preventDefault();
        esLogin = !esLogin;
        tituloAuth.textContent = esLogin ? 'Iniciar Sesión' : 'Crear Cuenta';
        btnAccion.textContent = esLogin ? 'Entrar' : 'Registrarme';
        toggleAuth.textContent = esLogin ? '¿No tienes cuenta? Regístrate' : '¿Ya tienes cuenta? Entra';
    });

    // Acción del botón (Entrar o Registrarse)
    btnAccion.addEventListener('click', async () => {
        const usuario = document.getElementById('usuario').value;
        const pass = document.getElementById('password').value;
        const ruta = esLogin ? '/auth/login' : '/auth/register'; // Ruta relativa

        if (!usuario || !pass) return alert("Llena los campos");

       
        const res = await fetch(ruta, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username: usuario, password: pass })
        });
        const data = await res.json();

        if (res.ok) {
            if (esLogin) {
                localStorage.setItem('token', data.token);
                mostrarMisViajes();
            } else {
                alert("¡Cuenta creada! Ahora inicia sesión.");
                toggleAuth.click(); 
            }
        } else {
            alert(data.error);
        }
    });

    function mostrarMisViajes() {
        vistaAuth.classList.add('oculto');
        vistaViajes.classList.remove('oculto');
        cargarViajes();
    }


    async function cargarViajes() {
        
        const res = await fetch('/api/mis-viajes', {
            headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
        });
        const viajes = await res.json();
        const lista = document.getElementById('lista-viajes');
        lista.innerHTML = '';
        
        viajes.forEach(v => {
            lista.innerHTML += `
                <div class="viaje-item">
                    <b>${v.destino}</b>
                    <button class="btn-rojo" onclick="borrar(${v.id})">X</button>
                </div>`;
        });
    }

    // Guardar nuevo viaje
    document.getElementById('btn-guardar-viaje').addEventListener('click', async () => {
        const destino = document.getElementById('select-destino').value;
       
        await fetch('/api/mis-viajes', {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${localStorage.getItem('token')}` 
            },
            body: JSON.stringify({ destino })
        });
        cargarViajes();
    });

    // Cerrar sesión
    document.getElementById('btn-salir').addEventListener('click', () => {
        localStorage.removeItem('token');
        location.reload();
    });

    window.borrar = async (id) => {

        await fetch(`/api/mis-viajes/${id}`, {
            method: 'DELETE',
            headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
        });
        cargarViajes();
    };
}