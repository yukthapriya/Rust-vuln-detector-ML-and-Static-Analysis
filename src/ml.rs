use linfa::traits::{Fit, Predict};
use linfa::Dataset;
use linfa_logistic::{LogisticRegression, FittedLogisticRegression};
use ndarray::{Array1, Array2};

type Model = FittedLogisticRegression<f32, i32>;

pub fn train_model() -> Result<Model, Box<dyn std::error::Error>> {
    let dataset = load_dataset("dataset/metadata.csv")?;
    let (train, test) = dataset.split_with_ratio(0.8);
    
    let model = LogisticRegression::default().fit(&train)?;
    
    let predictions = model.predict(&test);
    let accuracy = compute_accuracy(&predictions, test.targets())?;
    println!("Accuracy: {:.2}%", accuracy * 100.0);

    Ok(model)
}

fn compute_accuracy(predictions: &Array1<i32>, targets: &Array2<i32>) -> Result<f32, Box<dyn std::error::Error>> {
    let correct = predictions
        .iter()
        .zip(targets.column(0).iter())
        .filter(|(&pred, &target)| pred == target)
        .count();
    Ok(correct as f32 / predictions.len() as f32)
}

fn load_dataset(path: &str) -> Result<Dataset<f32, i32>, Box<dyn std::error::Error>> {
    let mut rdr = csv::Reader::from_path(path)?;
    let mut features = Vec::new();
    let mut labels = Vec::new();

    for result in rdr.records() {
        let record = result?;
        features.push(vec![
            record[0].parse()?,  // unsafe_block
            record[1].parse()?,  // path_traversal
            record[2].parse()?,  // command_injection
            record[3].parse()?,  // function_count
            record[4].parse()?,  // clippy_warnings
        ]);
        labels.push(if &record[5] == "unsafe" { 1 } else { 0 });
    }

    // Convert labels to 2D array with shape (n_samples, 1)
    let labels_2d = Array2::from_shape_vec((labels.len(), 1), labels)?;

    Ok(Dataset::new(
        Array2::from_shape_vec((features.len(), 5), features.concat())?,
        labels_2d
    ))
}