    function getCSRFToken() {
        return document.querySelector('meta[name="csrf-token"]').getAttribute('content')
    }

    // FUNCIONES GENÉRICAS

    function getBadgeClass(estado) {
        switch (estado) {
            case "COMPLETED":
                return "bg-success";
            case "FAILED":
                return "bg-danger";
            case "INSUFFICIENT_PERMISSIONS":
                return "bg-warning text-dark";
            case "RUNNING":
                return "bg-primary";
            case "QUEUED":
                return "bg-secondary";
            default:
                return "bg-dark";
        }
    }

    function getBadgeText(estado) {
        return estado === "INSUFFICIENT_PERMISSIONS" ? "SIN PERMISOS" : estado;
    }

    let evidencias = [];
    let evidenciasEliminadas = []
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
        const btnAltaServicio = document.querySelector("#alta_servicio");
        const formAltaServicio = document.querySelector("#formAltaServicio");
        const chkTodos = document.getElementById("chkTodos");


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
        initPasteEvidence();
        initGuardarFinding();

        // SWITCH AUTH CLOUD

        const authSwitch = document.getElementById("authSwitch");
        const roleSection = document.getElementById("roleSection");
        const keysSection = document.getElementById("keysSection");
        const authMethodInput = document.getElementById("auth_method");

        if (authSwitch && roleSection && keysSection) {

            authMethodInput.value = "keys";
            roleSection.style.display = "none";
            keysSection.style.display = "block";

            authSwitch.addEventListener("change", function () {

                if (this.checked) {
                    roleSection.style.display = "block";
                    keysSection.style.display = "none";
                    authMethodInput.value = "role";

                    // Limpiar keysSection
                    $('#access_key').val('');
                    $('#secret_key').val('');

                } else {
                    roleSection.style.display = "none";
                    keysSection.style.display = "block";
                    authMethodInput.value = "keys";

                    // Limpiar roleSection
                    $('#arn_role').val('');
                    $('#external_id').val('');
                    $('#role_access_key').val('');
                    $('#role_secret_key').val('');
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
            $('#lblServicioModal').text(servicioNombre);

            // Limpiar select
            $('#selectAccionAws').html('<option value="">Cargando...</option>');

            // Abrir modal
            const modal = new bootstrap.Modal(
                document.getElementById('mdlEjecutarEscaneo')
            );
            modal.show();

            // Llamada AJAX para traer acciones
            $.ajax({
                url: BASE_PATH + `/cloud/acciones/${servicioId}`,
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
                alert("Perfil actualizado correctamente.");
            });

        if (btnAltaServicio) {
            btnAltaServicio.addEventListener("click", () => {
                $("#mdlAltaServicio").modal("show")
            })
        }

        if (formAltaServicio) {
            formAltaServicio.addEventListener("submit", (e) => {
                e.preventDefault();
                const data = new FormData(formAltaServicio);
                fetch('/servicio/alta', {
                        method: 'POST',
                        headers: {
                            'X-CSRFToken': getCSRFToken()
                        },
                        body: data
                    })
                    .then(res => res.json())
                    .then(data => {
                        if (data.success) {
                            $("#mdlAltaServicio").modal("hide");
                            location.reload();
                        } else {
                            alert(data.mensaje || 'Error al guardar el servicio.');
                        }
                    })
                    .catch(() => alert('Error al guardar el servicio.'));
            });
        }

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
                url: BASE_PATH + "/proyecto/crear",
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

            const usaRole = document.getElementById('authSwitch').checked;

            // Deshabilitar inputs del bloque que NO se usa
            // para evitar que jQuery serialize envíe valores vacíos o duplicados
            if (usaRole) {
                $('#keysSection input').prop('disabled', true);
                $('#roleSection input').prop('disabled', false);
            } else {
                $('#roleSection input').prop('disabled', true);
                $('#keysSection input').prop('disabled', false);
            }

            const proyectoId = $('#cloud_proyecto_id').val();

            $.ajax({
                type: "POST",
                url: BASE_PATH + `/proyecto/${proyectoId}/cloud-config`,
                data: $(this).serialize(),
                dataType: "json",
                success: function (response) {
                    // Re-habilitar todos al terminar (por si el modal se vuelve a abrir)
                    $('#keysSection input, #roleSection input').prop('disabled', false);

                    if (response.success) {
                        alert(response.message);
                        $('#mdlGestionarConfiguracionCloud').modal('hide');
                        location.reload();
                    } else {
                        alert(response.message);
                    }
                },
                error: function (xhr) {
                    // Re-habilitar en caso de error también
                    $('#keysSection input, #roleSection input').prop('disabled', false);
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

            case 'OSINT':
                // Verificar que el elemento existe antes de asignar
                const inputOsint = document.getElementById('osint_proyecto_id');
                if (inputOsint) {
                    inputOsint.value = proyecto_id;
                } else {
                    console.error("Elemento osint_proyecto_id no encontrado");
                    return;
                }

                // Abrir el modal
                const modal = document.getElementById('mdlGestionarConfiguracionOsint');
                if (modal) {
                    new bootstrap.Modal(modal).show();
                } else {
                    console.error("Modal mdlGestionarConfiguracionOsint no encontrado");
                }
                break;

            case 'WEB':
                alert(proyecto_id)
                break;

            default:
                break;
        }
    }


    function ejecutarAccionCloud() {
        $('#btnEjecutarTodosServicio').off('click').on('click', async function () {
            const opciones = $('#selectAccionAws option').filter(function () {
                return $(this).val() !== '';
            });

            if (!opciones.length) return;

            const proyectoId = $('#cloudWorkspace').data('proyecto-id');
            const csrfToken = $('meta[name="csrf-token"]').attr('content');

            $('#mdlEjecutarEscaneo').modal('hide');

            for (const opt of opciones.toArray()) {
                await $.ajax({
                    type: 'POST',
                    url: BASE_PATH + '/cloud/run-roles',
                    contentType: 'application/json',
                    headers: {
                        'X-CSRFToken': csrfToken
                    },
                    data: JSON.stringify({
                        proyecto_id: proyectoId,
                        accion_id: $(opt).val()
                    })
                });
            }

            mostrarToast();
            const terminalBox = document.querySelector('.borde-terminal-salida');
            if (terminalBox) terminalBox.classList.add('borde-terminal-running');
            iniciarPollingCloud();
            cargarResultadosCloud();
        });

        $('#formEjecutarAccionCloud').on('submit', function (e) {
            e.preventDefault();

            const accionId = $('#selectAccionAws').val();
            const proyectoId = $('#cloudWorkspace').data('proyecto-id');
            const csrfToken = $('meta[name="csrf-token"]').attr('content');

            $.ajax({
                type: "POST",
                url: BASE_PATH + "/cloud/run-roles",
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

            const response = await fetch(BASE_PATH + `/cloud/resultados/${proyectoId}`);
            if (!response.ok) return;

            const data = await response.json();
            if (!data.success) return;

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
            url: BASE_PATH + `/cloud/resultados/${proyectoId}`,
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

        const response = await fetch(BASE_PATH + `/cloud/resultados/${proyectoId}`);

        if (!response.ok) return;

        const data = await response.json();
        if (!data.success) return;

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
        cargarFindingsImportados(proyectoId);
    }


    function actualizarTablaCloud(data) {

        const tbody = document.querySelector("#tablaEjecuciones tbody");
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

            const enEjecucion = contenido.estado === "RUNNING" || contenido.estado === "QUEUED";

            let colorIconoChecks = "bg-light text-secondary";
            let titleIconoChecks = "Sin hallazgos";
            let onclickAttr = "";

            if (!enEjecucion) {
                onclickAttr = `type="button" onclick="gestionarResultadoChecks('${contenido.id}')"`;

                const totalHallazgos = contenido.total_hallazgos || 0;
                const sinClasificar = contenido.hallazgos_sin_clasificar || 0;
                const sinVerificar = contenido.hallazgos_sin_verificar || 0;

                if (totalHallazgos === 0) {
                    colorIconoChecks = "bg-light text-secondary";
                    titleIconoChecks = "No posee hallazgos";
                } else {
                    const pendientes = [];
                    if (sinClasificar > 0) pendientes.push(`${sinClasificar} sin clasificar`);
                    if (sinVerificar > 0) pendientes.push(`${sinVerificar} sin verificar`);

                    if (pendientes.length > 0) {
                        colorIconoChecks = "bg-warning text-dark";
                        titleIconoChecks = pendientes.join(' y ');
                    } else {
                        colorIconoChecks = "bg-success text-light";
                        titleIconoChecks = `${totalHallazgos} hallazgo(s) clasificado(s) y verificado(s)`;
                    }
                }
            }
            const habilitarBtngestionarResultadoChecks = `class="badge ${colorIconoChecks}" title="${titleIconoChecks}" ${onclickAttr}`;
            tbody.innerHTML += `
            <tr>
                <td>${accion}</td>
                <td>
                    <span class="badge ${badgeClass}">
                        ${badgeText}
                    </span>
                </td>
                <td>
                <span ${habilitarBtngestionarResultadoChecks}><i class="bi bi-rocket-takeoff-fill"></i>
                    </span>
                </td>
            </tr>
        `;
        }
    }

    function gestionarResultadoChecks(cloud_ejecuciones_id) {
        const proyectoId = document
            .getElementById("cloudWorkspace")
            .dataset.proyectoId;
        window.location.href = BASE_PATH + `/proyecto/${proyectoId}/cloud/ejecucion/${cloud_ejecuciones_id}/hallazgos`;
    }


    function descargarDocAws(id, tipo) {
        window.location.href = BASE_PATH + `/proyecto/${id}/export/docx/aws/${tipo}`;
    }

    function descargarXlsxAws(id) {
        window.location.href = BASE_PATH + `/proyecto/${id}/export/xlsx/aws`;
    }

    function descargarDocOsint(id, tipo) {
        window.location.href = BASE_PATH + `/proyecto/${id}/export/docx/osint/${tipo}`;
    }


    function gestionarCheck(CLOUD_EJECUCION_ID) {
        alert(CLOUD_EJECUCION_ID)
    }

    // ← AGREGAR AQUÍ:
    async function cargarFindingsImportados(proyectoId) {
        try {
            const response = await fetch(BASE_PATH + `/proyecto/${proyectoId}/cloud/import-findings/lista`);
            const data = await response.json();

            const tbody = document.querySelector("#tablaImportados tbody");
            if (!tbody) return;

            tbody.innerHTML = "";

            data.forEach(item => {
                tbody.innerHTML += `
                <tr>
                    <td>${item.origen}</td>
                    <td><span class="badge bg-info">${item.total}</span></td>
                    <td>
                        <span class="badge bg-success" style="cursor: pointer;" 
                            title="Ver hallazgos importados"
                            onclick="verHallazgosImportados(${proyectoId}, '${item.origen}')">
                            <i class="bi bi-rocket-takeoff-fill"></i>
                        </span>
                    </td>
                </tr>
            `;
            });
        } catch (err) {
            console.error("[IMPORT ERROR]", err);
        }
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

    // ===============================
    // ABRIR MODAL Y CARGAR RULE
    // ===============================
    async function verificarHallazgo(finding_id) {

        limpiarModalFinding();

        try {
            const [findingRes, ruleRes_temp] = await Promise.all([
                fetch(BASE_PATH + `/proyecto/finding/detail/${finding_id}`).then(r => r.json()),
                // ruleRes lo cargamos después de tener el check_id
            ]);

            if (!findingRes.success) return;

            const findingData = findingRes.data.finding;
            const check_id = findingData.check_id;

            // Ahora cargamos la rule con el check_id real
            const ruleRes = await fetch(BASE_PATH + `/proyecto/security-rule/${check_id}`).then(r => r.json());

            // Setear hiddens
            $("#check_id").val(check_id);
            $("#proyecto_id").val(findingData.proyecto_id);
            $("#cloud_ejecucion_id").val(findingData.cloud_ejecucion_id);
            $("#resource_id").val(findingData.resource_id);
            $("#finding_id").val(finding_id);
            $("#finding_service").val(findingData.service);
            $("#finding_region").val(findingData.region || '');

            // Evidencias
            $("#evidence_preview").empty();
            (findingRes.data.evidencias_img || []).forEach(ev => {
                $("#evidence_preview").append(`
                <div class="evidence-item position-relative" data-id="${ev.id}">
                    <img src="/${ev.file_path}" width="300" height="300"
                        style="object-fit:cover;border:1px solid #444;border-radius:6px;">
                    <button type="button" class="btn btn-danger btn-sm delete-evidence">
                        <i class="bi bi-trash"></i>
                    </button>
                </div>`);
            });

            $("#finding_comment").val(findingData.finding_comment);
            $("#tool_output").val(findingData.inventory_data || '');

            // Referencias del finding importado (de referencias_data)
            if (findingData.referencias_data) {
                try {
                    const refsData = typeof findingData.referencias_data === 'string' ?
                        JSON.parse(findingData.referencias_data) :
                        findingData.referencias_data;

                    if (refsData.referencias && Array.isArray(refsData.referencias)) {
                        const refLinks = refsData.referencias.map(ref => `${ref.titulo}: ${ref.url}`).join('\n');
                        $("#rule_reference").val(refLinks);
                    }
                } catch (e) {
                    console.warn("Error parseando referencias_data:", e);
                }
            }

            // Severidades
            let selectSeverity = $("#rule_severity");
            selectSeverity.empty();
            ruleRes.severidades.forEach(s => {
                selectSeverity.append(`<option value="${s.id}" style="background-color:${s.color}">${s.nombre}</option>`);
            });

            // Estado Mitigacion (readonly text)
            let inputMitigacion = $("#estado_mitigacion");
            // Mapear estado_mitigacion a nombre (8=SIN MITIGAR, 9=MITIGADO)
            const estadosMitigacion = {
                8: "SIN MITIGAR",
                9: "MITIGADO"
            };
            inputMitigacion.val(estadosMitigacion[findingData.estado_mitigacion] || "DESCONOCIDO");

            // Rule
            if (!ruleRes.rule_exists) {
                $("#btnGuardarFinding").prop("disabled", true);
                $("#span_check_id").text(ruleRes.display_name);
                $("#text-regla, #icono-regla").removeClass("text-info text-success").addClass("text-warning");
                $("#icono-regla").removeClass("bi-check-circle bi-shield-exclamation").addClass("bi bi-shield-exclamation");
                $("#rule_id").val("");
                $("#rule_title, #rule_description, #rule_condition_logic, #rule_remediation, #rule_reference").val("");
                $("#aviso_ia_regla").hide();
            } else {
                $("#btnGuardarFinding").prop("disabled", false);
                const dataRule = ruleRes.data;
                $("#span_check_id").text(ruleRes.display_name);

                const validada = !!dataRule.validado_por;

                $("#text-regla, #icono-regla").removeClass("text-warning text-info text-success");
                $("#icono-regla").removeClass("bi-shield-exclamation bi-check-circle");

                if (validada) {
                    $("#text-regla, #icono-regla").addClass("text-success");
                    $("#icono-regla").addClass("bi bi-check-circle");
                    $("#aviso_ia_regla").hide();
                } else {
                    $("#text-regla, #icono-regla").addClass("text-info");
                    $("#icono-regla").addClass("bi bi-check-circle");
                    if (dataRule.creado_por_ia) {
                        $("#aviso_ia_regla").show();
                    } else {
                        $("#aviso_ia_regla").hide();
                    }
                }

                $("#rule_id").val(dataRule.id);
                $("#rule_title").val(dataRule.title);
                $("#rule_description").val(dataRule.description);
                $("#rule_condition_logic").val(dataRule.condition_logic);
                $("#rule_remediation").val(dataRule.remediation);
                $("#rule_reference").val(dataRule.reference);
                $("#rule_severity").val(dataRule.severidad_id);
            }

            $("#rule_severity").trigger("change");
            $("#mdlGestionarChecks").modal("show");

        } catch (err) {
            console.error("Error cargando datos:", err);
        }
    }

    function eliminarHallazgo(finding_id) {
        if (!confirm("¿Estás seguro que querés eliminar este hallazgo?")) return;

        // Extraer herramienta de la URL
        const urlPath = window.location.pathname;
        console.log("[DEBUG] URL Path:", urlPath);
        const match = urlPath.match(/importados\/([^/]+)/);
        console.log("[DEBUG] Regex Match:", match);
        const herramienta = match ? match[1] : null;
        console.log("[DEBUG] Herramienta extraída:", herramienta);

        fetch(BASE_PATH + `/proyecto/finding/eliminar/${finding_id}`, {
                method: 'POST',
                headers: {
                    "Content-Type": "application/json",
                    "X-CSRFToken": getCSRFToken()
                },
                body: JSON.stringify({
                    herramienta: herramienta
                })
            })
            .then(res => res.json())
            .then(res => {
                if (res.success) {
                    alert("Hallazgo eliminado correctamente");
                    location.reload();
                } else {
                    alert("Error al eliminar");
                }
            })
            .catch(err => console.error("ERROR:", err));
    }

    // ===============================
    // COLOR DEL SELECT SEVERITY
    // ===============================
    $("#rule_severity").change(function () {

        let color = $(this).find("option:selected").css("background-color")

        $(this).css({
            "background-color": color,
            "color": "#fff",
            "border-color": color
        })
    })


    // ===============================
    // BLOQUEAR ESCRITURA
    // ===============================
    $("#paste_evidence").on("keydown", function (e) {
        // permitir CTRL+V
        if (e.ctrlKey && e.key.toLowerCase() === "v") {
            return
        }
        e.preventDefault()
    })


    // ===============================
    // PEGAR CAPTURAS
    // ===============================
    // Mover fuera de cualquier función que se ejecute varias veces
    $("#paste_evidence").off("paste").on("paste", function (e) {
        e.preventDefault();
        let clipboard = e.originalEvent.clipboardData || e.clipboardData;
        let items = clipboard.items;
        let imageFound = false;
        for (let i = 0; i < items.length; i++) {
            let type = items[i].type;
            if (type.startsWith("image/")) {
                imageFound = true;
                let file = items[i].getAsFile();
                let reader = new FileReader();
                reader.onload = function (event) {
                    let img = `
                        <div class="evidence-item position-relative">
                            <img src="${event.target.result}"
                                width="300"
                                height="300"
                                style="object-fit:cover;border:1px solid #444;border-radius:6px;">
                            <button type="button"
                                class="btn btn-danger btn-sm btn-delete-evidence delete-evidence">
                                <i class="bi bi-trash"></i>
                            </button>
                        </div>`;
                    $("#evidence_preview").append(img);
                };
                reader.readAsDataURL(file);
            }
        }

        if (!imageFound) {
            alert("Solo puedes pegar capturas de pantalla.");
        }
    });


    // ===============================
    // ELIMINAR CAPTURA
    // ===============================
    $(document).on("click", ".delete-evidence", function () {
        $(this).closest(".evidence-item").remove()
    })


    // ===============================
    // LIMPIAR MODAL
    // ===============================
    function limpiarModalFinding() {
        $("#rule_id").val("")
        $("#rule_title").val("")
        $("#rule_description").val("")
        $("#rule_condition_logic").val("")
        $("#rule_remediation").val("")
        $("#rule_reference").val("")
        $("#rule_severity").val("1")
        $("#estados_findings_id").val("1")
        $("#finding_comment").val("")
        $("#paste_evidence").val("")
        $("#evidence_preview").empty()
        $("#tool_output").val("")
        $("#aviso_ia_regla").hide()
        $("#finding_region").val('')
    }


    // ===============================
    // LIMPIAR AL CERRAR MODAL
    // ===============================
    $("#mdlGestionarChecks").on("hidden.bs.modal", function () {
        limpiarModalFinding()
    });


    function guardarRule() {
        let data = {
            provider: "aws",
            service: $("#finding_service").val(),
            check_id: $("#check_id").val(),
            title: $("#rule_title").val(),
            description: $("#rule_description").val(),
            severidad_id: $("#rule_severity").val(),
            condition_logic: $("#rule_condition_logic").val(),
            remediation: $("#rule_remediation").val(),
            reference: $("#rule_reference").val()
        }

        fetch("/proyecto/security-rule", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "X-CSRFToken": document.querySelector('meta[name="csrf-token"]').content
                },
                body: JSON.stringify(data)
            })
            .then(res => res.json())
            .then(res => {
                if (res.success) {
                    $("#rule_id").val(res.rule_id);

                    $("#btnGuardarFinding").prop("disabled", false);

                    alert('Rule Information guardada correctamente!');
                    location.reload();
                }
            })
    }


    /* =====================================================
    GUARDAR FINDING
    ===================================================== */

    function guardarFinding() {

        $("#evidence_preview img").each(function () {
            const src = $(this).attr("src");

            if (src.startsWith("data:image")) {
                evidencias.push(src);
            }
        });

        let data = {
            proyecto_id: parseInt($("#proyecto_id").val()),
            cloud_ejecucion_id: parseInt($("#cloud_ejecucion_id").val()),
            security_rules_id: $("#rule_id").val() ? parseInt($("#rule_id").val()) : null,
            check_id: $("#check_id").val(),
            provider: "aws",
            service: $("#finding_service").val(),
            resource_id: $("#resource_id").val(),
            severidad_id: parseInt($("#rule_severity").val()),
            estados_findings_id: parseInt($("#estados_findings_id").val()),
            finding_comment: $("#finding_comment").val(),
            inventory_data: $("#tool_output").val(),
            evidencias: evidencias,
            evidencias_eliminadas: evidenciasEliminadas,
            region: $("#finding_region").val() || ''
        };

        fetch("/proyecto/finding", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "X-CSRFToken": getCSRFToken()
                },
                body: JSON.stringify(data)
            })
            .then(res => res.json())
            .then(res => {
                const finding_id = res.finding_id;
                return fetch(BASE_PATH + `/proyecto/finding/${finding_id}/verificar`, {
                    method: "POST",
                    headers: {
                        "X-CSRFToken": getCSRFToken()
                    }
                });
            })
            .then(res => res.json())
            .then(data => {
                evidenciasEliminadas = [];
                $("#mdlGestionarChecks").modal('hide');
                location.reload();
            })
            .catch(err => console.error("ERROR:", err));
    }

    function initPasteEvidence() {
        $("#paste_evidence").off("paste").on("paste", function (e) {
            e.preventDefault();
            let clipboard = e.originalEvent.clipboardData || e.clipboardData;
            let items = clipboard.items;
            let imageFound = false;

            for (let i = 0; i < items.length; i++) {
                if (items[i].type.startsWith("image/")) {
                    imageFound = true;
                    let file = items[i].getAsFile();
                    let reader = new FileReader();
                    reader.onload = function (event) {
                        let img = `
                        <div class="evidence-item position-relative">
                            <img src="${event.target.result}" width="300" height="300" 
                                 style="object-fit:cover;border:1px solid #444;border-radius:6px;">
                            <button type="button" 
                                    class="btn btn-danger btn-sm btn-delete-evidence delete-evidence">
                                <i class="bi bi-trash"></i>
                            </button>
                        </div>`;
                        $("#evidence_preview").append(img);
                    };
                    reader.readAsDataURL(file);
                }
            }

            if (!imageFound) alert("Solo puedes pegar capturas de pantalla.");
        });

        $(document).on("click", ".delete-evidence", function () {

            let container = $(this).closest(".evidence-item");
            let id = container.data("id");

            // solo si viene de DB
            if (id !== undefined) {
                evidenciasEliminadas.push(id);
            }

            container.remove();
        });
    }

    function initGuardarFinding() {
        $("#btnGuardarFinding").off("click").on("click", function (e) {
            e.preventDefault();
            guardarFinding();
        });
    }

    async function ejecutar_todos() {
        if (!confirm("¿Desea ejecutar todos los Servicios?")) return;
        const proyectoId = document.getElementById('cloudWorkspace').dataset.proyectoId;
        const csrfToken = document.querySelector('meta[name="csrf-token"]').content;

        // Traer todas las acciones
        const res = await fetch(BASE_PATH + `/cloud/acciones/all/${proyectoId}`);
        const data = await res.json();
        if (!data.success || !data.acciones.length) {
            alert("No se encontraron acciones para ejecutar");
            return;
        }
        // Encolar cada acción secuencialmente
        for (const accion of data.acciones) {
            await fetch('/cloud/run-roles', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrfToken
                },
                body: JSON.stringify({
                    proyecto_id: parseInt(proyectoId),
                    accion_id: accion.id
                })
            });
        }
        mostrarToast();
        iniciarPollingCloud();
        cargarResultadosCloud();
    }

    function pollEstadoReglas() {
        const pendientes = $('[data-regla-estado="sin_regla"]')
            .map(function () {
                return $(this).data('check-id');
            })
            .get();

        if (pendientes.length === 0) return;

        const interval = setInterval(() => {
            fetch('/proyecto/cloud/estado-reglas', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRFToken': getCSRFToken()
                    },
                    body: JSON.stringify({
                        check_ids: pendientes
                    })
                })
                .then(res => res.json())
                .then(data => {
                    let quedanPendientes = false;

                    for (const [checkId, estado] of Object.entries(data)) {
                        if (estado === 'sin_regla') {
                            quedanPendientes = true;
                            continue;
                        }

                        const celda = $(`[data-check-id="${checkId}"][data-regla-estado="sin_regla"]`);
                        if (celda.length === 0) continue;

                        celda.attr('data-regla-estado', estado);

                        if (estado === 'ia_sin_validar') {
                            celda.html('<i class="bi bi-shield-fill-check text-info" title="Regla generada por IA — sin validar"></i>');
                        } else if (estado === 'validada') {
                            celda.html('<i class="bi bi-shield-fill-check text-success" title="Regla validada"></i>');
                        }
                    }

                    if (!quedanPendientes) clearInterval(interval);
                });
        }, 4000);
    }

    function abrirModalImport() {
        $("#mdlAbrirModalImportArchivoFindings").modal("show")
    }

    // Validar archivo según herramienta
    $("#archivoImport").on("change", function () {
        const filename = this.files[0]?.name || "";
        const filename_lower = filename.toLowerCase();
        const herramienta = $("#herramientaImport").val();

        $("#frameworkInfo").hide();
        $("#alertFrameworkWarning").hide();

        if (filename) {
            // SOLO validar formato para Prowler Web
            if (herramienta === "prowler_web") {
                // Patrón válido: prowler-output-{HASH}.ocsf.json (sin guiones bajos)
                // Ejemplo: prowler-output-601227218666-20260714223844.ocsf.json
                const patron_valido = /^prowler-output-[a-z0-9]+-\d+\.ocsf\.json$/i;

                const es_valido = patron_valido.test(filename_lower);

                if (!es_valido) {
                    // Detectar si tiene un sufijo de framework
                    if (filename_lower.includes("_") && filename_lower.includes(".ocsf.json")) {
                        const match = filename_lower.match(/_(.+?)\.ocsf\.json/);
                        const sufijo = match ? match[1].toUpperCase() : "DESCONOCIDO";

                        $("#warningMessage").html(`
                            <strong>❌ Template específico '${sufijo}' no permitido</strong><br><br>
                            Este archivo contiene solo un framework específico de compliance.<br><br>
                            <strong>Usa el archivo COMPLETO</strong> de Prowler Web:<br>
                            <code>prowler-output-[ACCOUNT]-[TIMESTAMP].ocsf.json</code><br>
                            <em>Ejemplo: prowler-output-601227218666-20260714223844.ocsf.json</em>
                        `);
                        $("#alertFrameworkWarning").removeClass("alert-warning").addClass("alert-danger").show();
                    } else {
                        $("#warningMessage").html(`
                            <strong>❌ Formato de archivo inválido</strong><br><br>
                            Formato esperado: <code>prowler-output-[ACCOUNT]-[TIMESTAMP].ocsf.json</code><br>
                            <em>Ejemplo: prowler-output-601227218666-20260714223844.ocsf.json</em>
                        `);
                        $("#alertFrameworkWarning").removeClass("alert-warning").addClass("alert-danger").show();
                    }
                } else {
                    // Template completo válido
                    $("#frameworkName").text("Prowler Web OCSF Completo");
                    $("#frameworkInfo").show();
                }
            } else {
                // Para Prowler CLI: solo mostrar info, sin validación de formato
                $("#frameworkName").text(herramienta.replace('_', ' ').toUpperCase());
                $("#frameworkInfo").show();
            }
        }
    });

    $("#btnImportFindings").on("click", function () {
        const herramienta = $("#herramientaImport").val();
        const archivo = $("#archivoImport")[0].files[0];
        const proyectoId = $("#cloudWorkspace").data("proyecto-id");

        $("#errorArchivoImport").hide().text("");

        if (!archivo) {
            $("#errorArchivoImport").text("Seleccioná un archivo.").show();
            return;
        }

        const extensionesValidas = {
            "prowler_web": [".json"],
            "prowler_cli": [".json"],
            "scoutsuite_cli": [".js", ".json"], // ScoutSuite CLI exporta .js
            "scoutsuite_web": [".json"]
        };

        const ext = "." + archivo.name.split(".").pop().toLowerCase();
        if (!extensionesValidas[herramienta]?.includes(ext)) {
            $("#errorArchivoImport").text("Para " + herramienta + " el archivo debe ser " + extensionesValidas[herramienta].join(", ") + ".").show();
            return;
        }

        const formData = new FormData();
        formData.append("herramienta", herramienta);
        formData.append("archivo", archivo);

        const reader = new FileReader();
        reader.onload = function (e) {
            console.log("[IMPORT] JSON:", JSON.parse(e.target.result));
        };
        reader.readAsText(archivo);

        fetch(BASE_PATH + `/proyecto/${proyectoId}/cloud/import-findings`, {
                method: "POST",
                headers: {
                    "X-CSRFToken": $('meta[name="csrf-token"]').attr("content")
                },
                body: formData
            })
            .then(r => r.json())
            .then(data => {
                if (data.success) {
                    $("#mdlAbrirModalImportArchivoFindings").modal("hide");
                    cargarFindingsImportados(proyectoId);

                    let mensaje = `Se importaron ${data.imported} hallazgo(s) correctamente.`;
                    if (data.warning) {
                        mensaje += "\n\n" + data.warning;
                    }
                    alert(mensaje);
                } else {
                    $("#errorArchivoImport").text(data.message).show();
                }
            });
    });

    function verHallazgosImportados(proyectoId, herramienta) {
        window.location.href = BASE_PATH + `/proyecto/${proyectoId}/cloud/importados/${herramienta}/hallazgos`;
    }


    // ===============================
    // CHECKBOXES MASIVOS
    // ===============================
    const chkTodos = document.getElementById("chkTodos");
    if (chkTodos) {
        chkTodos.addEventListener("change", function () {
            document.querySelectorAll(".chk-finding").forEach(c => c.checked = this.checked);
            const accionesMasivas = document.getElementById("accionesMasivas");
            if (accionesMasivas) toggleAccionesMasivas();
        });
    }

    document.addEventListener("change", function (e) {
        if (e.target.classList.contains("chk-finding")) {
            toggleAccionesMasivas();
        }
    });

    function toggleAccionesMasivas() {
        const haySeleccionados = document.querySelectorAll(".chk-finding:checked").length > 0;
        const accionesMasivas = document.getElementById("accionesMasivas");
        if (accionesMasivas) {
            accionesMasivas.style.display = haySeleccionados ? "flex" : "none";
        }
    }

    function getSeleccionados() {
        return Array.from(document.querySelectorAll(".chk-finding:checked")).map(c => parseInt(c.value));
    }

    function verificarSeleccionados() {
        const ids = getSeleccionados();
        if (!ids.length) return;
        fetch("/proyecto/findings/verificar-masivo", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "X-CSRFToken": getCSRFToken()
            },
            body: JSON.stringify({
                finding_ids: ids
            })
        }).then(r => r.json()).then(data => {
            if (data.success) location.reload();
        });
    }

    function eliminarSeleccionados() {
        const ids = getSeleccionados();
        if (!ids.length) return;
        if (!confirm(`¿Eliminar ${ids.length} hallazgo(s)?`)) return;

        const urlPath = window.location.pathname;
        const match = urlPath.match(/importados\/([^/]+)/);
        const herramienta = match ? match[1] : null;

        fetch(BASE_PATH + "/proyecto/findings/eliminar-masivo", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "X-CSRFToken": $('meta[name="csrf-token"]').attr("content")
            },
            body: JSON.stringify({
                finding_ids: ids,
                herramienta: herramienta
            })
        }).then(r => r.json()).then(data => {
            if (data.success) location.reload();
        });
    }

    // ===============================
    // MITRE TÉCNICAS
    // ===============================
    let mitreTecnicas = {};

    function abrirFiltroMitre() {
        const proyectoId = document.getElementById('hallazgosWorkspace').dataset.proyectoId;
        fetch(BASE_PATH + `/proyecto/${proyectoId}/cloud/mitre-tecnicas`)
            .then(r => r.json())
            .then(data => {
                mitreTecnicas = data;
                $("#mdlFiltrarHallazgos").modal("show");
            });
    }

    const inputMitre = document.getElementById('inputMitreTecnica');
    if (inputMitre) {
        inputMitre.addEventListener('input', function () {
            const val = this.value.trim().toUpperCase();
            const sugerencias = document.getElementById('sugerenciasMitre');
            if (!sugerencias) return;

            if (val.length < 2) {
                sugerencias.style.display = 'none';
                document.getElementById('tbodyMitreFindings').innerHTML = '';
                document.getElementById('contenedorResultadosMitre').style.display = 'none';
                document.getElementById('sinResultadosMitre').style.display = 'none';
                return;
            }

            const matches = Object.keys(mitreTecnicas).filter(t => t.includes(val));
            sugerencias.innerHTML = matches.map(t =>
                `<a href="#" class="list-group-item list-group-item-action small py-1"
            onclick="seleccionarTecnica('${t}'); return false;">
            ${t} (${mitreTecnicas[t]} hallazgo/s)
        </a>`
            ).join('');
            sugerencias.style.display = matches.length > 0 ? 'block' : 'none';
        });
    }

    function seleccionarTecnica(id) {
        document.getElementById('inputMitreTecnica').value = id;
        document.getElementById('sugerenciasMitre').style.display = 'none';
    }

    function buscarPorMitre() {
        const tecnica = document.getElementById('inputMitreTecnica').value.trim().toUpperCase();
        const proyectoId = document.getElementById('hallazgosWorkspace').dataset.proyectoId;
        if (!tecnica) return;

        document.getElementById('tbodyMitreFindings').innerHTML = '';
        document.getElementById('contenedorResultadosMitre').style.display = 'none';
        document.getElementById('sinResultadosMitre').style.display = 'none';

        fetch(BASE_PATH + `/proyecto/${proyectoId}/cloud/mitre-findings/${tecnica}`)
            .then(r => r.json())
            .then(data => {
                const tbody = document.getElementById('tbodyMitreFindings');
                tbody.innerHTML = '';
                if (data.length === 0) {
                    document.getElementById('contenedorResultadosMitre').style.display = 'none';
                    document.getElementById('sinResultadosMitre').style.display = 'block';
                    return;
                }
                document.getElementById('sinResultadosMitre').style.display = 'none';
                document.getElementById('contenedorResultadosMitre').style.display = 'block';
                data.forEach(f => {
                    tbody.innerHTML += `
                    <tr>
                        <td>${f.resource_id}</td>
                        <td><span class="badge bg-dark text-warning">${f.check_id}</span></td>
                        <td>${f.service}</td>
                        <td>${f.severidad}</td>
                        <td>
                            <button onclick="verificarHallazgo(${f.finding_id})"
                                    class="btn btn-sm btn-secondary py-0 px-1">
                                <i class="bi bi-pencil-square"></i>
                            </button>
                        </td>
                    </tr>`;
                });
            });
    }



    // ===============================
    // OSINT CONFIGURATION
    // ===============================
    const mdlOsint = document.getElementById('mdlGestionarConfiguracionOsint');
    if (mdlOsint) {
        mdlOsint.addEventListener('show.bs.modal', async function () {
            console.log("EVENTO DISPARADO: show.bs.modal");
            const container = document.getElementById('osintConfigContainer');

            try {
                console.log("Fetching" +BASE_PATH+"/osint/config-tipos");
                const response = await fetch(BASE_PATH + '/osint/config-tipos', {
                    credentials: 'include'
                });

                if (!response.ok) {
                    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                }

                const tipos = await response.json();

                if (!Array.isArray(tipos) || tipos.length === 0) {
                    container.innerHTML = '<div class="alert alert-warning">No hay tipos de configuración disponibles</div>';
                    return;
                }

                container.innerHTML = tipos.map(tipo => {
                    return `<div class="mb-3">
                    <label for="config_${tipo.id}" class="form-label">
                        <strong>${tipo.nombre}</strong><br>
                        <small class="text-muted">${tipo.descripcion}</small>
                    </label>
                    <textarea class="form-control" id="config_${tipo.id}" name="${tipo.id}" rows="2" placeholder="${tipo.placeholder || ''}"></textarea>
                </div>`;
                }).join('');
            } catch (err) {
                console.error("Error cargando config tipos:", err);
                container.innerHTML = `<div class="alert alert-danger">
                <strong>Error:</strong> ${err.message}<br>
                <small>Endpoint: /osint/config-tipos</small>
            </div>`;
            }
        });
    } 

    const formOsintConfig = document.getElementById('formGestionarConfiguracionOSINT');
    if (formOsintConfig) {
        formOsintConfig.addEventListener('submit', function (e) {
            e.preventDefault();

            // ← LIMPIEZA AQUÍ, ANTES DE ENVIAR
            const allTextareas = this.querySelectorAll('textarea');
            allTextareas.forEach(ta => {
                let lines = ta.value.split('\n')
                    .map(line => line.trim())
                    .filter(line => line.length > 0);
                ta.value = lines.join('\n');
            });

            const proyectoId = document.getElementById('osint_proyecto_id').value;
            const formData = new FormData(this);

            fetch(BASE_PATH + `/proyecto/${proyectoId}/osint-config`, {
                    method: "POST",
                    headers: {
                        "X-CSRFToken": getCSRFToken()
                    },
                    body: formData
                })
                .then(res => res.json())
                .then(res => {
                    if (res.success) {
                        alert(res.message);
                        bootstrap.Modal.getInstance(document.getElementById('mdlGestionarConfiguracionOsint')).hide();
                        location.reload();
                    } else {
                        alert(res.message);
                    }
                })
                .catch(err => alert("Error al guardar: " + err));
        });
    }



    // ===============================
    // OSINT - EJECUTAR SERVICIOS
    // ===============================
    $(document).on('click', '.btn-servicio-osint', function (e) {
        e.preventDefault();

        const servicioId = $(this).val();
        const servicioNombre = $(this).text().trim();

        if (!confirm(`¿Ejecutar "${servicioNombre}"?`)) return;

        ejecutar_osint(servicioId, servicioNombre);
    });

    function ejecutar_osint(servicioId, nombreServicio) {
        const hallazgosEl = document.getElementById('hallazgosWorkspace');
        if (!hallazgosEl) return;

        const proyectoId = hallazgosEl.dataset.proyectoId;
        const terminal = document.getElementById('terminalOSINT');

        fetch('/osint/run', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': getCSRFToken()
                },
                body: JSON.stringify({
                    proyecto_id: proyectoId,
                    servicio_osint_id: servicioId
                })
            })
            .then(r => r.json())
            .then(data => {
                if (data.success) {
                    mostrarToast();

                    if (terminal) {
                        terminal.textContent = `[${new Date().toLocaleTimeString()}] Iniciando: ${nombreServicio}\n`;
                        terminal.textContent += 'Ejecutando...\n';
                    }

                    const terminalBox = document.querySelector('.borde-terminal-salida');
                    if (terminalBox) terminalBox.classList.add('borde-terminal-running');

                    iniciarPollingOSINT(data.ejecucion_id);
                } else {
                    alert("Error: " + data.message);
                }
            });
    }

    function iniciarPollingOSINT(ejecucionId) {
        let ultimoResultado = '';
        const terminal = document.getElementById('terminalOSINT');

        const interval = setInterval(() => {
            fetch(BASE_PATH + `/osint/status/${ejecucionId}`)
                .then(r => r.json())
                .then(status => {
                    if (!terminal) return;

                    let output = '';

                    // Estado general
                    output += `Estado: ${status.estado}\n`;
                    output += `Fecha Inicio: ${status.fecha_inicio || 'N/A'}\n`;
                    if (status.fecha_fin) output += `Fecha Fin: ${status.fecha_fin}\n`;
                    output += '═'.repeat(50) + '\n\n';

                    // Mostrar resultado
                    if (status.resultado) {
                        try {
                            const resultado = JSON.parse(status.resultado);
                            output += JSON.stringify(resultado, null, 2);
                            ultimoResultado = status.resultado;
                        } catch {
                            output += status.resultado;
                            ultimoResultado = status.resultado;
                        }
                    } else {
                        output += 'Cargando...';
                    }

                    // Mostrar error si existe
                    if (status.error) {
                        output += '\n\n ERROR:\n';
                        output += status.error;
                    }

                    terminal.textContent = output;
                    terminal.scrollTop = terminal.scrollHeight;

                    // ✅ Actualizar tabla SIEMPRE
                    cargarEjecucionesOSINT();

                    if (status.estado === 'COMPLETED' || status.estado === 'FAILED') {
                        clearInterval(interval);
                        const terminalBox = document.querySelector('.borde-terminal-salida');
                        if (terminalBox) terminalBox.classList.remove('borde-terminal-running');

                        // ✅ AGREGADO: Actualizar resultados finales
                        cargarResultadosOSINT();
                    }
                })
                .catch(err => {
                    console.error('[OSINT POLLING ERROR]', err);
                    if (terminal) {
                        terminal.textContent += '\n[ERROR EN POLLING] ' + err.message;
                    }
                });
        }, 2000);
    }

    function ejecutar_todos_osint() {
        // Confirmación ÚNICA: no vuelve a preguntar por cada servicio
        if (!confirm("¿Desea ejecutar todos los Servicios OSINT?")) return;

        const hallazgosEl = document.getElementById('hallazgosWorkspace');
        if (!hallazgosEl) return;
        const proyectoId = hallazgosEl.dataset.proyectoId;
        const terminal = document.getElementById('terminalOSINT');

        // El backend encola TODAS en cadena (una RUNNING, el resto QUEUED) y el
        // worker las procesa en secuencia por 'orden'. No hace falta esperar acá.
        fetch('/osint/run-all', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': getCSRFToken()
                },
                body: JSON.stringify({ proyecto_id: proyectoId })
            })
            .then(r => r.json())
            .then(data => {
                if (!data.success) {
                    alert("Error: " + data.message);
                    return;
                }
                mostrarToast();
                if (terminal) {
                    terminal.textContent = `[${new Date().toLocaleTimeString()}] ${data.total} servicios encolados. Ejecutando en orden...\n`;
                }
                const terminalBox = document.querySelector('.borde-terminal-salida');
                if (terminalBox) terminalBox.classList.add('borde-terminal-running');

                // Refrescar la tabla; el polling sigue mientras haya QUEUED o RUNNING
                cargarEjecucionesOSINT();
                if (!window.pollingOSINT) {
                    window.pollingOSINT = setInterval(cargarEjecucionesOSINT, 2000);
                }
            })
            .catch(err => alert("Error al encolar: " + err.message));
    }

    async function cargarEjecucionesOSINT() {
        const hallazgosEl = document.getElementById('hallazgosWorkspace');
        if (!hallazgosEl) return;

        const proyectoId = hallazgosEl.dataset.proyectoId;
        const tbody = document.querySelector('#tablaEscaneos tbody');
        if (!tbody) return;

        try {
            const response = await fetch(BASE_PATH + `/osint/ejecuciones/${proyectoId}`);
            const ejecuciones = await response.json();

            let html = '';
            let hayRunning = false;

            ejecuciones.forEach(exec => {
                let badgeClass = 'bg-secondary';
                let badgeText = exec.estado;

                if (exec.estado === 'COMPLETED') {
                    badgeClass = 'bg-success';
                } else if (exec.estado === 'FAILED') {
                    badgeClass = 'bg-danger';
                } else if (exec.estado === 'RUNNING') {
                    badgeClass = 'bg-primary';
                    hayRunning = true;
                } else if (exec.estado === 'QUEUED') {
                    badgeClass = 'bg-secondary';
                    hayRunning = true;  // seguir el polling mientras haya encolados
                }

                html += `
                <tr>
                    <td>${exec.nombre}</td>
                    <td>
                        <span class="badge ${badgeClass}">
                            ${badgeText}
                        </span>
                    </td>
                    <td>
                        <span class="badge bg-light text-secondary" title="Ver detalle" type="button" onclick="verDetalleOSINT(${exec.id})">
                            <i class="bi bi-rocket-takeoff-fill"></i>
                        </span>
                    </td>
                </tr>
            `;
            });

            tbody.innerHTML = html;

            // Mientras haya RUNNING o QUEUED, recargar cada 2 segundos
            if (hayRunning && !window.pollingOSINT) {
                window.pollingOSINT = setInterval(() => {
                    cargarEjecucionesOSINT();
                }, 2000);
            } else if (!hayRunning && window.pollingOSINT) {
                clearInterval(window.pollingOSINT);
                window.pollingOSINT = null;
                // Terminó toda la cadena: refrescar resultados y apagar el "running"
                const tb = document.querySelector('.borde-terminal-salida');
                if (tb) tb.classList.remove('borde-terminal-running');
                cargarResultadosOSINT();
            }
        } catch (err) {
            console.error('[OSINT] Error cargando ejecuciones:', err);
        }
    }

    document.addEventListener('DOMContentLoaded', function () {
        if (document.getElementById('hallazgosWorkspace')) {
            cargarEjecucionesOSINT();
            cargarResultadosOSINT();
        }
    });

    function cargarResultadosOSINT() {
        const hallazgosEl = document.getElementById('hallazgosWorkspace');
        if (!hallazgosEl) {
            return;
        }

        const proyectoId = hallazgosEl.dataset.proyectoId;
        const terminal = document.getElementById('terminalOSINT');

        if (!terminal) {
            return;
        }

        fetch(BASE_PATH + `/osint/ejecuciones/${proyectoId}`)
            .then(r => r.json())
            .then(ejecuciones => {
                let output = '';

                ejecuciones.forEach((exec, idx) => {
                    output += `${'═'.repeat(50)}\n`;
                    output += `[${idx + 1}] ${exec.nombre} - ${exec.estado}\n`;
                    output += `Fecha: ${exec.fecha_creacion}\n`;
                    output += `${'─'.repeat(50)}\n`;

                    if (exec.resultado) {
                        try {
                            const resultado = JSON.parse(exec.resultado);
                            output += JSON.stringify(resultado, null, 2);
                        } catch {
                            output += exec.resultado;
                        }
                    } else if (exec.error) {
                        output += `ERROR: ${exec.error}`;
                    } else {
                        output += 'Sin resultados';
                    }

                    output += '\n\n';
                });

                terminal.textContent = output || '';
                terminal.scrollTop = terminal.scrollHeight;

            })
            .catch(err => {
                console.error('[OSINT] Error:', err);
                terminal.textContent = 'Error: ' + err.message;
            });
    }

    function editarProyecto(params) {
        alert(params)
    }