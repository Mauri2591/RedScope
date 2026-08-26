function inhabilitarServicio(id) {
    alert('inhabilitarServicio')
    if (!confirm('¿Inhabilitar este servicio?')) return;
    fetch(BASE_PATH+`/servicio/${id}/inhabilitar`, {
        method: 'POST',
        headers: { 'X-CSRFToken': getCSRFToken() }
    })
    .then(res => res.json())
    .then(data => {
        if (data.success) location.reload();
        else alert('Error al inhabilitar el servicio.');
    })
    .catch(() => alert('Error al inhabilitar el servicio.'));
}