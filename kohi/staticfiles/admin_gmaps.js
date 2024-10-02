document.addEventListener("DOMContentLoaded", function() {
    function initialize() {
        const addressField = document.getElementById('id_address');
        const latitudeField = document.getElementById('id_latitude');
        const longitudeField = document.getElementById('id_longitude');

        const autocomplete = new google.maps.places.Autocomplete(addressField);
        autocomplete.addListener('place_changed', function () {
            const place = autocomplete.getPlace();
            if (!place.geometry) {
                return;
            }
            // Set latitude and longitude
            latitudeField.value = place.geometry.location.lat();
            longitudeField.value = place.geometry.location.lng();
        });
    }

    // Initialize the map once the page is fully loaded
    google.maps.event.addDomListener(window, 'load', initialize);
});
