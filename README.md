# log_analysis_task
How to run:
        - conda create -n zeek_analysis -f requirements.txt
        - conda activate zeek_analysis
        - pip install zat


Contents:
loading.py - helper scripts for working with the zeek log folder
loading.ipynb - script, which generates one dataframe containing the dataset from reduced logs
        - loading
        - selecting data (columns) for ML
        - merging logs into one df
        - data cleaning
            - filling missing values
            - converting to usable formats
            - dummy values for categorical data

pipeline.ipynb - script for data processing, training the model(s) and visualisations
        - feature selection 
        - normalisation
        - outlier detection
        - result analysis