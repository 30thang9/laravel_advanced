<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Password Reset Form</title>
    <!-- Bootstrap CSS -->
    <link href="https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
<div class="container mt-5">
    <div class="row justify-content-center">
        <div class="col-md-6">
            <div class="card">
                <div class="card-header">Reset Password</div>
                <div class="card-body">
                    <form id="resetPasswordForm">
                        <div class="form-group">
                            <label for="password">New Password:</label>
                            <input type="password" class="form-control" id="password" name="password" required>
                        </div>
                        <div class="form-group">
                            <label for="password_confirmation">Confirm Password:</label>
                            <input type="password" class="form-control" id="password_confirmation" name="password_confirmation" required>
                        </div>
                        <button type="submit" class="btn btn-primary">Reset Password</button>
                    </form>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- jQuery -->
<script src="https://ajax.googleapis.com/ajax/libs/jquery/3.5.1/jquery.min.js"></script>
<script>
    $(document).ready(function() {
        function getTokenFromUrl() {
            var url = window.location.href;
            var tokenIndex = url.lastIndexOf('/') + 1;
            var token = url.substr(tokenIndex);
            var tokenParts = token.split('?');
            return tokenParts[0];
        }

        function getEmailFromUrl() {
            var url = window.location.href;
            var emailIndex = url.indexOf('email=') + 'email='.length;
            var email = url.substr(emailIndex);
            return decodeURIComponent(email);
        }

        $('#resetPasswordForm').submit(function(event) {
            event.preventDefault();

            var formData = $(this).serialize();
            formData += '&token=' + getTokenFromUrl();
            formData += '&email=' + getEmailFromUrl();
            console.log(formData);
            $.ajax({
                url: 'http://laravel_advanced.loc/api/reset-password',
                method: 'POST',
                data: formData,
                dataType: 'json',
                success: function(response) {
                    alert(response.message);
                    window.location.href = 'http://laravel_advanced.loc/login';
                },
                error: function(xhr, status, error) {
                    alert('An error occurred while processing your request.');
                    console.error(xhr.responseText);
                }
            });
        });
    });

</script>
</body>
</html>
