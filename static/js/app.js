$(document).ready(function () {

    if ($('#tabla_inicio').length) {
        $('#tabla_inicio').DataTable();
    }

    if ($('#tabla_proyectos').length) {
        $('#tabla_proyectos').DataTable();
    }

    const modal = document.getElementById('mdlAltaProyecto');
    const tipo_servicio = document.getElementById('tipo_servicio');
    const contenedortipo_servicio = document.getElementById('contenedortipo_servicio');
    const contenedorAutenticado = document.getElementById('contenedorAutenticado');

    if (modal && tipo_servicio && contenedortipo_servicio) {

        modal.addEventListener('show.bs.modal', function (event) {

            const button = event.relatedTarget;
            const tipo = button.getAttribute('data-tipo-nombre');
            const tipoId = button.getAttribute('data-tipo-id');

            document.getElementById('tipo_proyecto_id').value = tipoId;

            tipo_servicio.innerHTML = '';

            if (tipo && tipo.toUpperCase() === "CLOUD") {

                contenedortipo_servicio.style.display = 'block';
                contenedorAutenticado.style.display = 'block';

                if (serviciosCloud && serviciosCloud.length > 0) {
                    serviciosCloud.forEach(servicio => {
                        const option = document.createElement("option");
                        option.value = servicio.id;
                        option.textContent = servicio.nombre;
                        tipo_servicio.appendChild(option);
                    });
                }

            } else {
                contenedortipo_servicio.style.display = 'none';
                contenedorAutenticado.style.display = 'none';
            }
        });
    }
    insertar_proyecto();
    ConfiguracionCloud();
    ejecutarAccionCloud();

    // ===============================
    // SWITCH AUTH CLOUD
    // ===============================

    const authSwitch = document.getElementById("authSwitch");
    const roleSection = document.getElementById("roleSection");
    const keysSection = document.getElementById("keysSection");
    const authMethodInput = document.getElementById("auth_method");

    if (authSwitch && roleSection && keysSection) {

        // Valor por defecto
        authMethodInput.value = "keys";
        roleSection.style.display = "none";
        keysSection.style.display = "block";

        authSwitch.addEventListener("change", function () {

            if (this.checked) {

                roleSection.style.display = "block";
                keysSection.style.display = "none";
                authMethodInput.value = "role";

                $('#access_key').val('');
                $('#secret_key').val('');

            } else {

                roleSection.style.display = "none";
                keysSection.style.display = "block";
                authMethodInput.value = "keys";

                $('#arn_role').val('');
                $('#external_id').val('');
            }

        });
    }

    $(document).on('click', '.btn-servicio-aws', function () {
        const servicioId = $(this).val();
        const servicioNombre = $(this).text().trim();

        // Guardar en hidden
        $('#cloud_servicio_aws_id').val(servicioId);

        // Cambiar título modal dinámicamente
        $('#exampleModalLabel').text('Ejecutar acción ' + servicioNombre);

        // Limpiar select
        $('#selectAccionAws').html('<option value="">Cargando...</option>');

        // Abrir modal
        const modal = new bootstrap.Modal(
            document.getElementById('mdlEjecutarEscaneo')
        );
        modal.show();

        // Llamada AJAX para traer acciones
        $.ajax({
            url: `/cloud/acciones/${servicioId}`,
            type: 'GET',
            success: function (response) {

                if (response.success) {

                    // Si no trae acciones
                    if (!response.acciones || response.acciones.length === 0) {

                        $('#selectAccionAws')
                            .html('<option value="">No posee</option>')
                            .prop('disabled', true);
                    } else {
                        let opciones = '';
                        response.acciones.forEach(function (accion) {
                            opciones += `
                        <option value="${accion.id}" 
                            data-handler="${accion.handler}" 
                            title="${accion.descripcion}">
                            ${accion.nombre_ui}
                        </option>
                    `;
                        });

                        $('#selectAccionAws')
                            .html(opciones)
                            .prop('disabled', false);
                    }

                } else {

                    $('#selectAccionAws')
                        .html('<option value="">Error cargando acciones</option>')
                        .prop('disabled', true);
                }
            },
            error: function () {

                $('#selectAccionAws')
                    .html('<option value="">Error cargando acciones</option>')
                    .prop('disabled', true);
            }
        });
    });

    if (document.getElementById('cloudWorkspace')) {
        cargarResultadosCloud();
    }


    const modalPerfil = document.getElementById("mdlPerfilUsuario");
    if (modalPerfil) {
        modalPerfil.addEventListener("show.bs.modal", function () {
            $("#flexSwitchCheckChecked").prop("checked", false);
            $("#password").prop("disabled", true).val("");
        });
    }
    $("#flexSwitchCheckChecked").on("change", function () {
        $("#password").prop("disabled", !this.checked);
    });

    document.getElementById("actualizarPerfilUsuario")
.addEventListener("submit", function (e) {

    const emailValue = document.querySelector("input[name='email']").value.trim();
    const switchChecked = document.getElementById("flexSwitchCheckChecked").checked;
    const passwordValue = document.getElementById("password").value.trim();

    // Validar email obligatorio
    if (emailValue === "") {
        e.preventDefault();
        alert("El email es obligatorio.");
        return false;
    }

    // Validar password si switch activado
    if (switchChecked && passwordValue === "") {
        e.preventDefault();
        alert("Debe ingresar un password si habilita el cambio.");
        return false;
    }

    // Si pasa validaciones
    alert("Perfil actualizado correctamente.");

});



});

document.addEventListener("DOMContentLoaded", function () {

    const authSwitch = document.getElementById("authSwitch");
    const roleSection = document.getElementById("roleSection");
    const keysSection = document.getElementById("keysSection");

    if (!authSwitch) return;

    authSwitch.addEventListener("change", function () {

        if (this.checked) {
            roleSection.style.display = "block";
            keysSection.style.display = "none";

            document.getElementById("access_key").value = "";
            document.getElementById("secret_key").value = "";
        } else {
            roleSection.style.display = "none";
            keysSection.style.display = "block";

            document.getElementById("arn_role").value = "";
            document.getElementById("external_id").value = "";
        }

    });

});



function insertar_proyecto() {
    $('#formAltaProyecto').on('submit', function (e) {
        e.preventDefault();
        $.ajax({
            url: "/proyecto/crear",
            type: "POST",
            data: $(this).serialize(),
            success: function (response) {
                if (response.success) {
                    alert(response.message);
                    $('#mdlAltaProyecto').modal('hide');
                    // Opcional: recargar tabla
                    location.reload();
                } else {
                    alert(response.message);
                }
            },
            error: function (xhr) {
                alert("Error en el servidor");
            }
        });
    });
}

function ConfiguracionCloud() {
    $('#formGestionarConfiguracionCloud').on('submit', function (e) {
        e.preventDefault();
        const proyectoId = $('#cloud_proyecto_id').val();
        $.ajax({
            type: "POST",
            url: `/proyecto/${proyectoId}/cloud-config`,
            data: $(this).serialize(),
            dataType: "json",
            success: function (response) {
                if (response.success) {
                    alert(response.message);
                    $('#mdlGestionarConfiguracionCloud').modal('hide');
                    location.reload();
                } else {
                    alert(response.message);
                }
            },
            error: function (xhr) {
                console.log("STATUS:", xhr.status);
                console.log("RESPONSE:", xhr.responseText);
                alert("Error en el servidor");
            }
        });
    });
}


function gestionarConfiguracion(proyecto_id, tipo_proyecto) {
    switch (tipo_proyecto) {
        case 'CLOUD':
            $('#cloud_proyecto_id').val(proyecto_id);
            $("#mdlGestionarConfiguracionCloud").modal('show')
            break;

        case 'WEB':
            alert(proyecto_id)
            break;

        default:
            break;
    }
}


function ejecutarAccionCloud() {
    $('#formEjecutarAccionCloud').on('submit', function (e) {
        e.preventDefault();

        const accionId = $('#selectAccionAws').val();
        const proyectoId = $('#cloudWorkspace').data('proyecto-id');
        const csrfToken = $('meta[name="csrf-token"]').attr('content');

        $.ajax({
            type: "POST",
            url: "/cloud/run-roles",
            contentType: "application/json",
            headers: {
                "X-CSRFToken": csrfToken
            },
            data: JSON.stringify({
                proyecto_id: proyectoId,
                accion_id: accionId
            }),
            success: function (response) {
                if (response.success) {

                    mostrarToast();

                    const terminalBox = document.querySelector('.borde-terminal-salida');
                    terminalBox.classList.add('borde-terminal-running');

                    iniciarPollingCloud();

                    // 🔹 SOLO refrescá estados actuales
                    cargarResultadosCloud();

                    $('#mdlEjecutarEscaneo').modal('hide');

                } else {
                    alert("Error al ejecutar");
                }
            },
            error: function (xhr) {
                console.log(xhr.responseText);
            }
        });
    });
}


function iniciarPollingCloud() {

    const proyectoId = document
        .getElementById('cloudWorkspace')
        .dataset.proyectoId;

    const interval = setInterval(async () => {

        const response = await fetch(`/cloud/resultados/${proyectoId}`);
        if (!response.ok) return;

        const data = await response.json();
        if (!data.success) return;

        // 👉 actualizar tabla en tiempo real
        actualizarTablaCloud(data.data);

        let algunaCorriendo = false;

        for (const [accion, contenido] of Object.entries(data.data)) {
            if (contenido.estado === "QUEUED" ||
                contenido.estado === "RUNNING") {
                algunaCorriendo = true;
                break;
            }
        }

        if (!algunaCorriendo) {
            clearInterval(interval);

            const terminalBox = document.querySelector('.borde-terminal-salida');
            terminalBox.classList.remove('borde-terminal-running');

            cargarResultadosCloud();
        }

    }, 3000);
}



function actualizarTerminal(proyectoId) {

    $.ajax({
        type: "GET",
        url: `/cloud/resultados/${proyectoId}`,
        success: function (response) {

            if (!response.success) return;

            let salida = "====================================\n";

            response.data.forEach(item => {

                salida += `Acción: ${item.nombre_ui}\n`;
                salida += "------------------------------------\n";

                if (item.estado === "COMPLETED") {
                    salida += item.resultado + "\n\n";
                } else if (item.estado === "FAILED") {
                    salida += "ERROR:\n";
                    salida += item.error + "\n\n";
                } else {
                    salida += "Ejecutando...\n\n";
                }

            });

            $('.terminal-salida-herramienta').text(salida);

        },
        error: function (xhr) {
            console.log(xhr.responseText);
        }
    });

}

async function cargarResultadosCloud() {

    const container = document.getElementById('cloudWorkspace');
    const proyectoId = container.dataset.proyectoId;

    const response = await fetch(`/cloud/resultados/${proyectoId}`);

    if (!response.ok) return;

    const data = await response.json();
    if (!data.success) return;

    // 🔥 ESTA LÍNEA FALTABA
    actualizarTablaCloud(data.data);

    let salida = "";

    for (const [accion, contenido] of Object.entries(data.data)) {

        salida += `======================================\n`;
        salida += `Acción: ${accion}\n`;
        salida += `--------------------------------------\n`;
        salida += `Estado: ${contenido.estado}\n\n`;

        if (contenido.estado === "FAILED") {

            salida += JSON.stringify({
                error: contenido.error || "Sin detalle",
                status: "FAILED"
            }, null, 2);

        } else if (contenido.estado === "RUNNING" || contenido.estado === "QUEUED") {

            salida += `Ejecutando...\n`;

        } else if (contenido.estado === "COMPLETED") {

            salida += `${contenido.resultado || "Sin resultados"}\n`;

        }

        salida += `\n======================================\n\n`;
    }

    document.querySelector(".terminal-salida-herramienta").textContent = salida;
}


function actualizarTablaCloud(data) {

    const tbody = document.querySelector("#tablaEjecuciones tbody");
    console.log(data);

    if (!tbody) return;

    tbody.innerHTML = "";

    for (const [accion, contenido] of Object.entries(data)) {

        let badgeClass = "";
        let badgeText = contenido.estado;

        switch (contenido.estado) {
            case "COMPLETED":
                badgeClass = "bg-success";
                break;
            case "FAILED":
                badgeClass = "bg-danger";
                break;
            case "INSUFFICIENT_PERMISSIONS":
                badgeClass = "bg-warning text-dark";
                badgeText = "SIN PERMISOS";
                break;
            case "RUNNING":
                badgeClass = "bg-primary";
                break;
            case "QUEUED":
                badgeClass = "bg-secondary";
                break;
            default:
                badgeClass = "bg-dark";
        }

        const habilitarBtnGestionarResultadoEscaneo = contenido.estado == "RUNNING" || contenido.estado == "QUEUED" ? "" : `class="badge bg-success text-light" type=button onclick=gestionarResultadoEscaneo('${contenido.id}')`;
        tbody.innerHTML += `
            <tr>
                <td>${accion}</td>
                <td>
                    <span class="badge ${badgeClass}">
                        ${badgeText}
                    </span>
                </td>
                <td>
                <span ${habilitarBtnGestionarResultadoEscaneo} class="badge bg-light text-secondary"><i class="bi bi-rocket-takeoff-fill"></i>
                    </span>
                </td>
            </tr>
        `;
    }
}

function gestionarResultadoEscaneo(id) {
    alert(id)
}

function mostrarToast() {
    var toastEl = document.getElementById('toastEscaneo');
    var toast = new bootstrap.Toast(toastEl, {
        delay: 1000
    });
    toast.show();
}

function actualizarPerfil() {
    $("#mdlPerfilUsuario").modal("show")
}