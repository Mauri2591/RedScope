const csrfToken = document.querySelector('meta[name="csrf-token"]').content;

function getCSRFToken() {
    return csrfToken;
}

$(document).ready(function () {

    let tabla = $('#tabla_clientes').DataTable();
    let altaCliente = document.querySelector("#alta_cliente");
    let formAltaCliente = document.querySelector("#formAltaCliente");

    function limpiarModalAltaCliente() {
        $("#nombre").val('');
        $("#cuit").val('');
        $("#referencia").val('');
    }

    if (altaCliente) {
        altaCliente.addEventListener("click", () => {
            limpiarModalAltaCliente();
            $("#mdlAltaCliente").modal("show");
        });
    }

    if (formAltaCliente) {
        formAltaCliente.addEventListener("submit", (e) => {
            e.preventDefault();
            let data = new FormData(formAltaCliente);
            fetch('/cliente/alta', {
                method: 'POST',
                headers: { 'X-CSRFToken': csrfToken },
                body: data
            })
            .then(res => {
                if (res.ok) {
                    alert('Cliente creado correctamente');
                    $("#mdlAltaCliente").modal("hide");
                    location.reload();
                } else {
                    alert('Error al crear el Cliente');
                }
            })
            .catch(() => alert('Error al guardar el cliente.'));
        });
    }

    $('#np_tipo_proyecto').on('change', function () {
        const tipo = $(this).find('option:selected').data('tipo');
        if (tipo === 'CLOUD') {
            $('#np_contenedor_servicio').show();
        } else {
            $('#np_contenedor_servicio').hide();
        }
    });

    $('#formNuevoProyecto').on('submit', function (e) {
        e.preventDefault();
        const data = new FormData(this);
        fetch('/proyecto/crear', {
            method: 'POST',
            headers: { 'X-CSRFToken': csrfToken },
            body: data
        })
        .then(res => res.json())
        .then(data => {
            if (data.success) {
                $('#mdlNuevoProyecto').modal('hide');
                alert('Proyecto creado correctamente.');
            } else {
                alert(data.message || 'Error al crear el proyecto.');
            }
        });
    });

});

function abrirModalProyecto(clienteId) {
    $('#np_cliente_id').val(clienteId);
    $('#np_titulo').val('');
    $('#np_tipo_proyecto').trigger('change');
    $('#mdlNuevoProyecto').modal('show');
}

function inhabilitarCliente(id) {
    if (!confirm('¿Desea inhabilitar este cliente?')) return;
    fetch(`/cliente/${id}/inhabilitar`, {
        method: 'POST',
        headers: { 'X-CSRFToken': csrfToken }
    })
    .then(res => {
        if (res.ok) location.reload();
        else alert('Error al inhabilitar el cliente.');
    })
    .catch(() => alert('Error al inhabilitar el cliente.'));
}