import express from 'express';
import { createTour, deleteTour, getAllTour, getFeaturedTour, getSingleTour, getTourBySearch, getTourCount, updateTour }  from '../contollers/tourController.js';
const router = express.Router();

//create new tour
router.post('/',createTour);

//update Tour
router.put('/:id',updateTour);

// delete tour
router.delete('/:id',deleteTour);


//get single tour
router.get('/:id',getSingleTour);

//get all  tour
router.get('/',getAllTour);

//get tour by search
router.get("/search/getTourBySearch",getTourBySearch)

router.get("/search/getFeaturedTours",getFeaturedTour)

router.get("/search/getTourCount",getTourCount)

export default router;