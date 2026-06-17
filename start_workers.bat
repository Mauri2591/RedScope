@echo off
start cmd /k "rq worker --worker-class rq.worker.SimpleWorker --url redis://localhost:6379"
start cmd /k "rq worker ia --worker-class rq.worker.SimpleWorker --url redis://localhost:6379"