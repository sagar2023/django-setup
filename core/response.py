from rest_framework.response import Response


class SuccessResponse(Response):
    """
        SuccessResponse class used to handle the success response.
    """
    def __init__(self, data=None, extra_data=None, status=200):
        """
            override the default constructor
        :param data:
        :param status:
        """
        if extra_data:
            data.update(extra_data)

        result = {"data": data, "status": status}
        super().__init__(result, status)
