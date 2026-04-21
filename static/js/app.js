    function getCSRFToken() {
        return document.querySelector('meta[name="csrf-token"]').getAttribute('content')
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
                url: `/proyecto/${proyectoId}/cloud-config`,
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

            const habilitarBtngestionarResultadoChecks = contenido.estado == "RUNNING" || contenido.estado == "QUEUED" ? "" : `class="badge bg-success text-light" type=button onclick=gestionarResultadoChecks('${contenido.id}')`;
            tbody.innerHTML += `
                <tr>
                    <td>${accion}</td>
                    <td>
                        <span class="badge ${badgeClass}">
                            ${badgeText}
                        </span>
                    </td>
                    <td>
                    <span ${habilitarBtngestionarResultadoChecks} class="badge bg-light text-secondary"><i class="bi bi-rocket-takeoff-fill"></i>
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
        window.location.href = `/proyecto/${proyectoId}/cloud/ejecucion/${cloud_ejecuciones_id}/hallazgos`;
    }

    function descargarDoc(id) {
        window.location.href = `/proyecto/${id}/export/docx`;
    }

    function descargarXlsx(id) {
        window.location.href = `/proyecto/${id}/export/xlsx`;
    }

    function gestionarCheck(CLOUD_EJECUCION_ID) {
        alert(CLOUD_EJECUCION_ID)
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
                fetch(`/proyecto/finding/detail/${finding_id}`).then(r => r.json()),
                // ruleRes lo cargamos después de tener el check_id
            ]);

            if (!findingRes.success) return;

            const findingData = findingRes.data.finding;
            const check_id = findingData.check_id;

            // Ahora cargamos la rule con el check_id real
            const ruleRes = await fetch(`/proyecto/security-rule/${check_id}`).then(r => r.json());

            // Setear hiddens
            $("#check_id").val(check_id);
            $("#proyecto_id").val(findingData.proyecto_id);
            $("#cloud_ejecucion_id").val(findingData.cloud_ejecucion_id);
            $("#resource_id").val(findingData.resource_id);
            $("#finding_id").val(finding_id);

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

            // Severidades
            let selectSeverity = $("#rule_severity");
            selectSeverity.empty();
            ruleRes.severidades.forEach(s => {
                selectSeverity.append(`<option value="${s.id}" style="background-color:${s.color}">${s.nombre}</option>`);
            });

            // Estados
            let selectStatus = $("#estados_findings_id");
            selectStatus.empty();
            ruleRes.combo_findings.forEach(e => {
                selectStatus.append(`<option value="${e.id}">${e.nombre}</option>`);
            });
            selectStatus.val(findingData.estados_findings_id);

            // Rule
            if (!ruleRes.rule_exists) {
                $("#btnGuardarFinding").prop("disabled", true);
                $("#span_check_id").text(ruleRes.display_name);
                $("#text-regla, #icono-regla").removeClass("text-info").addClass("text-warning");
                $("#icono-regla").removeClass("bi-check-circle bi-shield-exclamation").addClass("bi bi-shield-exclamation");
                $("#rule_id").val("");
                $("#rule_title, #rule_description, #rule_condition_logic, #rule_remediation, #rule_reference").val("");
            } else {
                $("#btnGuardarFinding").prop("disabled", false);
                const dataRule = ruleRes.data;
                $("#span_check_id").text(ruleRes.display_name);
                $("#text-regla, #icono-regla").removeClass("text-warning").addClass("text-info");
                $("#icono-regla").removeClass("bi-shield-exclamation bi-check-circle").addClass("bi bi-check-circle");
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

        fetch(`/proyecto/finding/eliminar/${finding_id}`, {
                method: 'POST',
                headers: {
                    "Content-Type": "application/json",
                    "X-CSRFToken": getCSRFToken()
                }
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
    // 🔹 Mover fuera de cualquier función que se ejecute varias veces
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
            service: "iam",
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
                    // ✅ Asignar rule_id para que guardarFinding lo use
                    $("#rule_id").val(res.rule_id);

                    // ✅ Habilitar botón guardar
                    $("#btnGuardarFinding").prop("disabled", false);

                    alert('Rule Information guardada correctamente!');
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
            service: "s3",
            resource_id: $("#resource_id").val(),
            severidad_id: parseInt($("#rule_severity").val()),
            estados_findings_id: parseInt($("#estados_findings_id").val()),
            finding_comment: $("#finding_comment").val(),
            evidencias: evidencias,
            evidencias_eliminadas: evidenciasEliminadas
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
                const finding_id = res.finding_id; // 👈 viene del backend
                return fetch(`/proyecto/finding/${finding_id}/verificar`, {
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

            console.log("ID:", id);

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