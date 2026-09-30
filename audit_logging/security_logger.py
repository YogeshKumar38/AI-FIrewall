import time

from database.database import initialize_database
from database.repository import save_security_result


class SecurityLogger:

    def __init__(self, log_prompt_content: bool = False):
        self.log_prompt_content = log_prompt_content
        initialize_database()

    def log(self, result):
        start_time = time.perf_counter()

        request_id = save_security_result(
            result=result,
            processing_time_ms=(
                time.perf_counter() - start_time
            ) * 1000,
            log_prompt_content=self.log_prompt_content,
        )

        return request_id
