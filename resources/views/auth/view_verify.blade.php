<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Email Verification</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
<div class="container mt-5">
    <h1>Email Verification</h1>
    <p>Please click the button below to verify your email:</p>

    <button id="verifyEmailBtn" class="btn btn-primary">Verify Email</button>
</div>

<script src="https://ajax.googleapis.com/ajax/libs/jquery/3.6.0/jquery.min.js"></script>
<script>
    $(document).ready(function() {
        $('#verifyEmailBtn').click(function() {
            // Lấy đoạn path từ URL
            var path = window.location.pathname;
            // Tách lấy phần id từ đoạn path
            var userId = path.substring(path.lastIndexOf('/') + 1);

            // Trích xuất các tham số từ URL
            var urlParams = new URLSearchParams(window.location.search);
            var expires = urlParams.get('expires');
            var signature = urlParams.get('signature');
            var hash = urlParams.get('hash');
            console.log(signature);
            console.log(expires);
            console.log(hash);
            // Gửi yêu cầu AJAX đến endpoint của API
            $.ajax({
                url: 'http://laravel_advanced.loc/api/verify-email/' + userId, // Đường dẫn của API
                type: 'POST',
                headers: {
                    'X-CSRF-TOKEN': $('meta[name="csrf-token"]').attr('content')
                },
                data: {
                    expires: expires,
                    signature: signature,
                    hash: hash
                },
                success: function(response) {
                    // Xử lý kết quả từ server nếu cần
                    console.log(response);
                },
                error: function(xhr, status, error) {
                    console.error(error);

                    var errorMessage = xhr.responseJSON.message;
                    console.error(errorMessage);
                }
            });
        });
    });

</script>
</body>
</html>
